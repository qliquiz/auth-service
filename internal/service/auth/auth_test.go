package auth_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"auth-service/gen/api"
	"auth-service/internal/domain/models"
	jwtlib "auth-service/internal/lib/jwt"
	"auth-service/internal/lib/password"
	"auth-service/internal/lib/token"
	sessionRepo "auth-service/internal/repository/session"
	userRepo "auth-service/internal/repository/user"
	"auth-service/internal/service/auth"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	testJWTSecret  = "unit-test-secret-min-32-chars!!!"
	testRefreshTTL = 7 * 24 * time.Hour
)

// ── Test fixture ──────────────────────────────────────────────────────────────

type fixture struct {
	svc     *auth.AuthService
	uRepo   *mockUserRepo
	sRepo   *mockSessionRepo
	jwtMgr  *jwtlib.Manager
	miniRed *miniredis.Miniredis
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	uRepo := &mockUserRepo{}
	sRepo := &mockSessionRepo{}
	jwtMgr := jwtlib.New(testJWTSecret, 15*time.Minute)

	svc := auth.New(uRepo, sRepo, jwtMgr, redisClient, slog.Default(), testRefreshTTL)

	return &fixture{
		svc:     svc,
		uRepo:   uRepo,
		sRepo:   sRepo,
		jwtMgr:  jwtMgr,
		miniRed: mr,
	}
}

// ctxWithBearerToken injects a valid JWT into the gRPC incoming context.
func (f *fixture) ctxWithBearerToken(t *testing.T, userID, email string) context.Context {
	t.Helper()
	tok, err := f.jwtMgr.GenerateAccessToken(userID, email, []string{"user"})
	require.NoError(t, err)
	md := metadata.Pairs("authorization", "Bearer "+tok)
	return metadata.NewIncomingContext(context.Background(), md)
}

// fakeUser returns a *models.User with a real argon2id hash of "password123".
func fakeUser(t *testing.T) *models.User {
	t.Helper()
	hash, err := password.Hash("password123")
	require.NoError(t, err)
	return &models.User{
		ID:           "user-uuid-001",
		Email:        "alice@example.com",
		PasswordHash: hash,
	}
}

// ── Register ──────────────────────────────────────────────────────────────────

func TestRegister_Success(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	f.uRepo.On("Create", mock.Anything, "alice@example.com", mock.AnythingOfType("string")).
		Return(&models.User{ID: "user-uuid-001", Email: "alice@example.com"}, nil)

	resp, err := f.svc.Register(context.Background(), &api.RegisterRequest{
		Email:    "alice@example.com",
		Password: "password123",
	})

	require.NoError(t, err)
	assert.Equal(t, "user-uuid-001", resp.UserId)
	f.uRepo.AssertExpectations(t)
}

func TestRegister_InvalidEmail(t *testing.T) {
	t.Parallel()

	cases := []string{"", "notanemail", "@nodomain", "noatsign.com"}

	for _, email := range cases {
		t.Run(email, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)

			_, err := f.svc.Register(context.Background(), &api.RegisterRequest{
				Email:    email,
				Password: "password123",
			})

			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			f.uRepo.AssertNotCalled(t, "Create")
		})
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, err := f.svc.Register(context.Background(), &api.RegisterRequest{
		Email:    "alice@example.com",
		Password: "short",
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	f.uRepo.AssertNotCalled(t, "Create")
}

func TestRegister_EmailAlreadyExists(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	f.uRepo.On("Create", mock.Anything, "alice@example.com", mock.AnythingOfType("string")).
		Return((*models.User)(nil), userRepo.ErrAlreadyExists)

	_, err := f.svc.Register(context.Background(), &api.RegisterRequest{
		Email:    "alice@example.com",
		Password: "password123",
	})

	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

// ── Login ─────────────────────────────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	user := fakeUser(t)

	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)

	resp, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
		DeviceId: "device-abc",
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)

	// Validate the returned access token.
	jwtMgr := jwtlib.New(testJWTSecret, 15*time.Minute)
	claims, err := jwtMgr.ValidateAccessToken(resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.Email, claims.Email)
}

func TestLogin_UserNotFound(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	f.uRepo.On("GetByEmail", mock.Anything, "ghost@example.com").
		Return((*models.User)(nil), userRepo.ErrNotFound)

	_, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    "ghost@example.com",
		Password: "password123",
	})

	require.Error(t, err)
	// Must return Unauthenticated, NOT NotFound — don't leak user existence.
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestLogin_WrongPassword(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	user := fakeUser(t)

	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)

	_, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "wrongpassword",
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	f.sRepo.AssertNotCalled(t, "Create")
}

func TestLogin_StoresHashedTokenNotPlain(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	user := fakeUser(t)

	var capturedSession *models.Session
	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).
		Run(func(args mock.Arguments) {
			capturedSession = args.Get(1).(*models.Session)
		}).
		Return(nil)

	resp, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
	})
	require.NoError(t, err)

	// The stored hash must NOT equal the plain token.
	require.NotNil(t, capturedSession)
	assert.NotEqual(t, resp.RefreshToken, capturedSession.TokenHash)
	// But hashing the plain token must equal the stored hash.
	assert.Equal(t, token.Hash(resp.RefreshToken), capturedSession.TokenHash)
}

// ── ValidateToken ─────────────────────────────────────────────────────────────

func TestValidateToken_Valid(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	tok, err := f.jwtMgr.GenerateAccessToken("user-001", "alice@example.com", []string{"user", "admin"})
	require.NoError(t, err)

	resp, err := f.svc.ValidateToken(context.Background(), &api.ValidateTokenRequest{Token: tok})
	require.NoError(t, err)
	assert.True(t, resp.Valid)
	assert.Equal(t, "user-001", resp.UserId)
	assert.Equal(t, []string{"user", "admin"}, resp.Roles)
}

func TestValidateToken_Expired(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	expiredMgr := jwtlib.New(testJWTSecret, -time.Second)
	tok, err := expiredMgr.GenerateAccessToken("user-001", "alice@example.com", nil)
	require.NoError(t, err)

	resp, err := f.svc.ValidateToken(context.Background(), &api.ValidateTokenRequest{Token: tok})
	require.NoError(t, err) // ValidateToken never returns gRPC error, only valid=false
	assert.False(t, resp.Valid)
}

func TestValidateToken_Malformed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	cases := []string{"", "garbage", "a.b.c"}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			resp, err := f.svc.ValidateToken(context.Background(), &api.ValidateTokenRequest{Token: tc})
			require.NoError(t, err)
			assert.False(t, resp.Valid)
		})
	}
}

// ── RefreshToken ──────────────────────────────────────────────────────────────

func TestRefreshToken_Success_CacheHit(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// Simulate Login: call it to populate Redis cache.
	user := fakeUser(t)
	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)

	loginResp, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
	})
	require.NoError(t, err)

	// Now refresh — should hit Redis, not DB.
	f.sRepo.On("DeleteByTokenHash", mock.Anything, token.Hash(loginResp.RefreshToken)).Return(nil)
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)

	refreshResp, err := f.svc.RefreshToken(context.Background(), &api.RefreshTokenRequest{
		RefreshToken: loginResp.RefreshToken,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, refreshResp.AccessToken)
	assert.NotEmpty(t, refreshResp.RefreshToken)
	// Refresh token must rotate (new one issued).
	assert.NotEqual(t, loginResp.RefreshToken, refreshResp.RefreshToken)
	// New access token must be valid.
	jwtMgr := jwtlib.New(testJWTSecret, 15*time.Minute)
	claims, err := jwtMgr.ValidateAccessToken(refreshResp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
	// DB GetByTokenHash must NOT have been called (cache hit path).
	f.sRepo.AssertNotCalled(t, "GetByTokenHash")
}

func TestRefreshToken_Success_CacheMiss_DBFallback(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	plainToken, hashedToken, err := token.Generate()
	require.NoError(t, err)

	// Redis is empty → DB fallback.
	dbSession := &models.Session{
		ID:        "sess-001",
		UserID:    "user-001",
		UserEmail: "alice@example.com",
		TokenHash: hashedToken,
		DeviceID:  "device-xyz",
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	f.sRepo.On("GetByTokenHash", mock.Anything, hashedToken).Return(dbSession, nil)
	f.sRepo.On("DeleteByTokenHash", mock.Anything, hashedToken).Return(nil)
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)

	resp, err := f.svc.RefreshToken(context.Background(), &api.RefreshTokenRequest{
		RefreshToken: plainToken,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	f.sRepo.AssertExpectations(t)
}

func TestRefreshToken_TokenNotFound(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	plainToken, _, _ := token.Generate()

	f.sRepo.On("GetByTokenHash", mock.Anything, mock.AnythingOfType("string")).
		Return((*models.Session)(nil), sessionRepo.ErrNotFound)

	_, err := f.svc.RefreshToken(context.Background(), &api.RefreshTokenRequest{
		RefreshToken: plainToken,
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRefreshToken_SessionExpired(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	plainToken, hashedToken, _ := token.Generate()

	expiredSession := &models.Session{
		ID:        "sess-expired",
		UserID:    "user-001",
		UserEmail: "alice@example.com",
		TokenHash: hashedToken,
		ExpiresAt: time.Now().Add(-time.Hour), // in the past
	}
	f.sRepo.On("GetByTokenHash", mock.Anything, hashedToken).Return(expiredSession, nil)
	f.sRepo.On("DeleteByTokenHash", mock.Anything, hashedToken).Return(nil)

	_, err := f.svc.RefreshToken(context.Background(), &api.RefreshTokenRequest{
		RefreshToken: plainToken,
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	// Expired session must be cleaned up from DB.
	f.sRepo.AssertCalled(t, "DeleteByTokenHash", mock.Anything, hashedToken)
}

func TestRefreshToken_OldTokenInvalidatedAfterRotation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	user := fakeUser(t)
	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)
	// First Create: Login session. Second Create: new session after refresh.
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil).Twice()

	loginResp, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
	})
	require.NoError(t, err)

	oldToken := loginResp.RefreshToken
	oldHash := token.Hash(oldToken)

	f.sRepo.On("DeleteByTokenHash", mock.Anything, oldHash).Return(nil)

	_, err = f.svc.RefreshToken(context.Background(), &api.RefreshTokenRequest{
		RefreshToken: oldToken,
	})
	require.NoError(t, err)

	// Redis must no longer contain the old token hash.
	exists := f.miniRed.Exists("refresh:" + oldHash)
	assert.False(t, exists, "old refresh token must be removed from cache after rotation")
}

// ── Logout ────────────────────────────────────────────────────────────────────

func TestLogout_Success(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	plainToken, hashedToken, _ := token.Generate()
	f.sRepo.On("DeleteByTokenHash", mock.Anything, hashedToken).Return(nil)

	resp, err := f.svc.Logout(context.Background(), &api.LogoutRequest{
		RefreshToken: plainToken,
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	f.sRepo.AssertExpectations(t)
}

func TestLogout_ClearsRedisCache(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	user := fakeUser(t)
	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)

	loginResp, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
	})
	require.NoError(t, err)

	plainToken := loginResp.RefreshToken
	hashedToken := token.Hash(plainToken)

	// Key must be present before logout.
	require.True(t, f.miniRed.Exists("refresh:"+hashedToken))

	f.sRepo.On("DeleteByTokenHash", mock.Anything, hashedToken).Return(nil)

	_, err = f.svc.Logout(context.Background(), &api.LogoutRequest{RefreshToken: plainToken})
	require.NoError(t, err)

	// Key must be gone after logout.
	assert.False(t, f.miniRed.Exists("refresh:"+hashedToken))
}

// ── LogoutAll ─────────────────────────────────────────────────────────────────

func TestLogoutAll_Success(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctx := f.ctxWithBearerToken(t, "user-001", "alice@example.com")
	f.sRepo.On("DeleteAllByUserID", mock.Anything, "user-001").
		Return([]string{"hash-1", "hash-2", "hash-3"}, nil)

	resp, err := f.svc.LogoutAll(ctx, &api.LogoutAllRequest{})
	require.NoError(t, err)
	assert.EqualValues(t, 3, resp.SessionsRevoked)
}

func TestLogoutAll_NoAuthHeader(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, err := f.svc.LogoutAll(context.Background(), &api.LogoutAllRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	f.sRepo.AssertNotCalled(t, "DeleteAllByUserID")
}

func TestLogoutAll_InvalidToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	md := metadata.Pairs("authorization", "Bearer thisisgarbage")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := f.svc.LogoutAll(ctx, &api.LogoutAllRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ── ListSessions ──────────────────────────────────────────────────────────────

func TestListSessions_Success(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctx := f.ctxWithBearerToken(t, "user-001", "alice@example.com")
	sessions := []*models.Session{
		{ID: "sess-1", DeviceID: "ios-device", UserAgent: "MyApp/1.0", IPAddress: "1.2.3.4"},
		{ID: "sess-2", DeviceID: "web-browser", UserAgent: "Chrome/120", IPAddress: "5.6.7.8"},
	}
	f.sRepo.On("ListByUserID", mock.Anything, "user-001").Return(sessions, nil)

	resp, err := f.svc.ListSessions(ctx, &api.ListSessionsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 2)
	assert.Equal(t, "sess-1", resp.Sessions[0].SessionId)
	assert.Equal(t, "ios-device", resp.Sessions[0].DeviceId)
	assert.Equal(t, "sess-2", resp.Sessions[1].SessionId)
}

func TestListSessions_EmptyList(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctx := f.ctxWithBearerToken(t, "user-001", "alice@example.com")
	f.sRepo.On("ListByUserID", mock.Anything, "user-001").Return([]*models.Session{}, nil)

	resp, err := f.svc.ListSessions(ctx, &api.ListSessionsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.Sessions)
}

func TestListSessions_NoAuthHeader(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, err := f.svc.ListSessions(context.Background(), &api.ListSessionsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ── RevokeSession ─────────────────────────────────────────────────────────────

func TestRevokeSession_Success(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctx := f.ctxWithBearerToken(t, "user-001", "alice@example.com")
	f.sRepo.On("DeleteByID", mock.Anything, "sess-to-revoke", "user-001").Return("some-hash", nil)

	resp, err := f.svc.RevokeSession(ctx, &api.RevokeSessionRequest{SessionId: "sess-to-revoke"})
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestRevokeSession_NotFound(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctx := f.ctxWithBearerToken(t, "user-001", "alice@example.com")
	f.sRepo.On("DeleteByID", mock.Anything, "nonexistent", "user-001").
		Return("", sessionRepo.ErrNotFound)

	_, err := f.svc.RevokeSession(ctx, &api.RevokeSessionRequest{SessionId: "nonexistent"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestRevokeSession_CannotRevokeOtherUsersSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// user-002 tries to revoke a session that belongs to user-001.
	// The repo enforces ownership via WHERE user_id = $2 — returns ErrNotFound.
	ctx := f.ctxWithBearerToken(t, "user-002", "bob@example.com")
	f.sRepo.On("DeleteByID", mock.Anything, "sess-of-user-001", "user-002").
		Return("", sessionRepo.ErrNotFound)

	_, err := f.svc.RevokeSession(ctx, &api.RevokeSessionRequest{SessionId: "sess-of-user-001"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}
