//go:build e2e

// Package e2e runs full end-to-end tests against a real in-process gRPC server,
// a real PostgreSQL container (testcontainers), and an in-memory Redis (miniredis).
package e2e

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"auth-service/gen/api"
	jwtlib "auth-service/internal/lib/jwt"
	"auth-service/internal/repository/session"
	"auth-service/internal/repository/testutil"
	"auth-service/internal/repository/user"
	"auth-service/internal/service/auth"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// ── Test server setup ─────────────────────────────────────────────────────────

type testServer struct {
	client  api.AuthServiceClient
	jwtMgr  *jwtlib.Manager
	miniRed *miniredis.Miniredis
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	pool := testutil.NewPostgresPool(t)

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	redisClient := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	jwtMgr := jwtlib.New("e2e-test-secret-min-32-chars!!!!", 15*time.Minute)

	uRepo := user.New(pool)
	sRepo := session.New(pool)
	svc := auth.New(uRepo, sRepo, jwtMgr, redisClient, slog.Default(), 7*24*time.Hour)

	// Start gRPC server over in-memory bufconn.
	lis := bufconn.Listen(bufSize)
	grpcSrv := grpc.NewServer()
	auth.Register(grpcSrv, svc)

	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.GracefulStop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return &testServer{
		client:  api.NewAuthServiceClient(conn),
		jwtMgr:  jwtMgr,
		miniRed: mr,
	}
}

// authCtx builds a context with the Authorization header set.
func (s *testServer) authCtx(t *testing.T, accessToken string) context.Context {
	t.Helper()
	md := metadata.Pairs("authorization", "Bearer "+accessToken)
	return metadata.NewOutgoingContext(context.Background(), md)
}

// ── Full flow tests ───────────────────────────────────────────────────────────

func TestE2E_RegisterAndLogin(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	ctx := context.Background()

	regResp, err := srv.client.Register(ctx, &api.RegisterRequest{
		Email:    "alice@example.com",
		Password: "securepassword1",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, regResp.UserId)

	loginResp, err := srv.client.Login(ctx, &api.LoginRequest{
		Email:    "alice@example.com",
		Password: "securepassword1",
		DeviceId: "iphone-abc",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, loginResp.AccessToken)
	assert.NotEmpty(t, loginResp.RefreshToken)
}

func TestE2E_Register_DuplicateEmail(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	ctx := context.Background()

	_, err := srv.client.Register(ctx, &api.RegisterRequest{
		Email:    "dup@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	_, err = srv.client.Register(ctx, &api.RegisterRequest{
		Email:    "dup@example.com",
		Password: "differentpassword",
	})
	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestE2E_Login_WrongPassword(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	ctx := context.Background()

	_, err := srv.client.Register(ctx, &api.RegisterRequest{
		Email:    "bob@example.com",
		Password: "correctpassword",
	})
	require.NoError(t, err)

	_, err = srv.client.Login(ctx, &api.LoginRequest{
		Email:    "bob@example.com",
		Password: "wrongpassword",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestE2E_ValidateToken(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	ctx := context.Background()

	regResp, err := srv.client.Register(ctx, &api.RegisterRequest{
		Email:    "carol@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	loginResp, err := srv.client.Login(ctx, &api.LoginRequest{
		Email:    "carol@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	valResp, err := srv.client.ValidateToken(ctx, &api.ValidateTokenRequest{
		Token: loginResp.AccessToken,
	})
	require.NoError(t, err)
	assert.True(t, valResp.Valid)
	assert.Equal(t, regResp.UserId, valResp.UserId)
}

func TestE2E_TokenRotation(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	ctx := context.Background()

	_, err := srv.client.Register(ctx, &api.RegisterRequest{
		Email:    "dave@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	loginResp, err := srv.client.Login(ctx, &api.LoginRequest{
		Email:    "dave@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	oldRefreshToken := loginResp.RefreshToken

	// Refresh with the old token → get new tokens.
	refreshResp, err := srv.client.RefreshToken(ctx, &api.RefreshTokenRequest{
		RefreshToken: oldRefreshToken,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, refreshResp.AccessToken)
	assert.NotEmpty(t, refreshResp.RefreshToken)
	assert.NotEqual(t, oldRefreshToken, refreshResp.RefreshToken)

	// Using the old token again must fail — it has been rotated out.
	_, err = srv.client.RefreshToken(ctx, &api.RefreshTokenRequest{
		RefreshToken: oldRefreshToken,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err),
		"old refresh token must be invalid after rotation")
}

func TestE2E_Logout(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	ctx := context.Background()

	_, err := srv.client.Register(ctx, &api.RegisterRequest{
		Email:    "eve@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	loginResp, err := srv.client.Login(ctx, &api.LoginRequest{
		Email:    "eve@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	_, err = srv.client.Logout(ctx, &api.LogoutRequest{
		RefreshToken: loginResp.RefreshToken,
	})
	require.NoError(t, err)

	// After logout, the refresh token must be invalid.
	_, err = srv.client.RefreshToken(ctx, &api.RefreshTokenRequest{
		RefreshToken: loginResp.RefreshToken,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestE2E_LogoutAll(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	ctx := context.Background()

	_, err := srv.client.Register(ctx, &api.RegisterRequest{
		Email:    "frank@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	// Create 3 sessions from different devices.
	tokens := make([]string, 3)
	for i, device := range []string{"ios", "android", "web"} {
		resp, lerr := srv.client.Login(ctx, &api.LoginRequest{
			Email:    "frank@example.com",
			Password: "password123",
			DeviceId: device,
		})
		require.NoError(t, lerr)
		tokens[i] = resp.RefreshToken
	}

	// Obtain a fresh access token for the auth header.
	loginResp, err := srv.client.Login(ctx, &api.LoginRequest{
		Email:    "frank@example.com",
		Password: "password123",
		DeviceId: "admin-session",
	})
	require.NoError(t, err)

	authCtx := srv.authCtx(t, loginResp.AccessToken)
	logoutAllResp, err := srv.client.LogoutAll(authCtx, &api.LogoutAllRequest{})
	require.NoError(t, err)
	// 4 sessions: 3 + the admin-session itself.
	assert.EqualValues(t, 4, logoutAllResp.SessionsRevoked)

	// All previously issued refresh tokens must now be dead.
	for _, tok := range tokens {
		_, err = srv.client.RefreshToken(ctx, &api.RefreshTokenRequest{RefreshToken: tok})
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	}
}

func TestE2E_ListSessions(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	ctx := context.Background()

	_, err := srv.client.Register(ctx, &api.RegisterRequest{
		Email:    "grace@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	for _, device := range []string{"phone", "tablet"} {
		_, err = srv.client.Login(ctx, &api.LoginRequest{
			Email:    "grace@example.com",
			Password: "password123",
			DeviceId: device,
		})
		require.NoError(t, err)
	}

	loginResp, err := srv.client.Login(ctx, &api.LoginRequest{
		Email:    "grace@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	authCtx := srv.authCtx(t, loginResp.AccessToken)
	listResp, err := srv.client.ListSessions(authCtx, &api.ListSessionsRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(listResp.Sessions), 3)

	for _, s := range listResp.Sessions {
		assert.NotEmpty(t, s.SessionId)
		assert.NotZero(t, s.CreatedAt)
	}
}

func TestE2E_RevokeSession(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	ctx := context.Background()

	_, err := srv.client.Register(ctx, &api.RegisterRequest{
		Email:    "henry@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	// Session A — the one we will revoke.
	sessAResp, err := srv.client.Login(ctx, &api.LoginRequest{
		Email:    "henry@example.com",
		Password: "password123",
		DeviceId: "device-A",
	})
	require.NoError(t, err)

	// Session B — used for auth and must survive.
	sessBResp, err := srv.client.Login(ctx, &api.LoginRequest{
		Email:    "henry@example.com",
		Password: "password123",
		DeviceId: "device-B",
	})
	require.NoError(t, err)

	// List sessions to get session A's ID.
	authCtx := srv.authCtx(t, sessBResp.AccessToken)
	listResp, err := srv.client.ListSessions(authCtx, &api.ListSessionsRequest{})
	require.NoError(t, err)

	// Find the session for device-A.
	var sessAID string
	for _, s := range listResp.Sessions {
		if s.DeviceId == "device-A" {
			sessAID = s.SessionId
			break
		}
	}
	require.NotEmpty(t, sessAID, "device-A session must be in the list")

	// Revoke session A using session B's access token.
	_, err = srv.client.RevokeSession(authCtx, &api.RevokeSessionRequest{SessionId: sessAID})
	require.NoError(t, err)

	// session A's refresh token must now be invalid.
	_, err = srv.client.RefreshToken(ctx, &api.RefreshTokenRequest{
		RefreshToken: sessAResp.RefreshToken,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	// session B must still work.
	_, err = srv.client.RefreshToken(ctx, &api.RefreshTokenRequest{
		RefreshToken: sessBResp.RefreshToken,
	})
	require.NoError(t, err)
}
