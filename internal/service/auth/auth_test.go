package auth_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"auth-service/gen/api"
	"auth-service/internal/domain/models"
	"auth-service/internal/lib/bruteforce"
	jwtlib "auth-service/internal/lib/jwt"
	"auth-service/internal/lib/password"
	"auth-service/internal/lib/token"
	auditRepo "auth-service/internal/repository/audit"
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

	svc := auth.New(uRepo, sRepo, jwtMgr, redisClient, nil, nil, slog.Default(), testRefreshTTL)

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
	f.sRepo.On("RotateToken", mock.Anything, token.Hash(loginResp.RefreshToken), mock.AnythingOfType("*models.Session")).Return(nil)

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
	f.sRepo.On("RotateToken", mock.Anything, hashedToken, mock.AnythingOfType("*models.Session")).Return(nil)

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
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)

	loginResp, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
	})
	require.NoError(t, err)

	oldToken := loginResp.RefreshToken
	oldHash := token.Hash(oldToken)

	f.sRepo.On("RotateToken", mock.Anything, oldHash, mock.AnythingOfType("*models.Session")).Return(nil)

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

func TestLogout_AlreadyRevoked_IdempotentSuccess(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	plainToken, hashedToken, _ := token.Generate()
	f.sRepo.On("DeleteByTokenHash", mock.Anything, hashedToken).Return(sessionRepo.ErrNotFound)

	_, err := f.svc.Logout(context.Background(), &api.LogoutRequest{RefreshToken: plainToken})
	require.NoError(t, err, "already-revoked token must return success (idempotent)")
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

// ── Brute-force protection ─────────────────────────────────────────────────────

// newFixtureWithGuard creates a fixture with a real bruteforce.Guard backed by
// miniredis. maxAttempts controls how many wrong passwords trigger a lockout.
func newFixtureWithGuard(t *testing.T, maxAttempts int) *fixture {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	uRepo := &mockUserRepo{}
	sRepo := &mockSessionRepo{}
	jwtMgr := jwtlib.New(testJWTSecret, 15*time.Minute)
	guard := bruteforce.New(redisClient, maxAttempts, time.Minute, 15*time.Minute)

	svc := auth.New(uRepo, sRepo, jwtMgr, redisClient, nil, guard, slog.Default(), testRefreshTTL)

	return &fixture{
		svc:     svc,
		uRepo:   uRepo,
		sRepo:   sRepo,
		jwtMgr:  jwtMgr,
		miniRed: mr,
	}
}

// TestLogin_BruteForce_LocksOnNthFailure verifies that the Nth consecutive wrong
// password triggers account lockout (ResourceExhausted), while earlier attempts
// return the ordinary Unauthenticated error.
func TestLogin_BruteForce_LocksOnNthFailure(t *testing.T) {
	t.Parallel()
	f := newFixtureWithGuard(t, 3)
	user := fakeUser(t)

	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)

	ctx := context.Background()
	for i := range 2 {
		_, err := f.svc.Login(ctx, &api.LoginRequest{
			Email:    user.Email,
			Password: "wrong-password",
		})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err), "attempt %d should be Unauthenticated", i+1)
	}

	// Third failure reaches the threshold — account is locked immediately.
	_, err := f.svc.Login(ctx, &api.LoginRequest{
		Email:    user.Email,
		Password: "wrong-password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err), "Nth failure must lock the account")
}

// TestLogin_BruteForce_BlockedAfterLock verifies that once an account is locked,
// even a correct password is rejected and the user repository is not consulted.
func TestLogin_BruteForce_BlockedAfterLock(t *testing.T) {
	t.Parallel()
	f := newFixtureWithGuard(t, 2)
	user := fakeUser(t)

	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)

	ctx := context.Background()
	// Two wrong attempts lock the account (2nd returns ResourceExhausted directly).
	for range 2 {
		_, _ = f.svc.Login(ctx, &api.LoginRequest{
			Email:    user.Email,
			Password: "wrong-password",
		})
	}

	// Correct password — still blocked because IsLocked fires before any DB lookup.
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)
	_, err := f.svc.Login(ctx, &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
	})
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	// GetByEmail must have been called only for the 2 wrong attempts, not the locked one.
	f.uRepo.AssertNumberOfCalls(t, "GetByEmail", 2)
}

// TestLogin_BruteForce_ResetOnSuccess verifies that a successful login resets the
// failure counter so that subsequent wrong attempts start fresh.
func TestLogin_BruteForce_ResetOnSuccess(t *testing.T) {
	t.Parallel()
	f := newFixtureWithGuard(t, 3)
	user := fakeUser(t)

	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)

	ctx := context.Background()
	// Two wrong attempts — below threshold, account not locked.
	for range 2 {
		_, _ = f.svc.Login(ctx, &api.LoginRequest{
			Email:    user.Email,
			Password: "wrong-password",
		})
	}

	// Successful login must reset the counter.
	_, err := f.svc.Login(ctx, &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
	})
	require.NoError(t, err, "correct credentials should succeed before lock threshold")

	// Two more wrong attempts — counter starts from zero again, no lockout.
	for i := range 2 {
		_, err := f.svc.Login(ctx, &api.LoginRequest{
			Email:    user.Email,
			Password: "wrong-password",
		})
		assert.Equal(t, codes.Unauthenticated, status.Code(err),
			"post-reset attempt %d must be Unauthenticated, not ResourceExhausted", i+1)
	}
}

// ── Audit logging ──────────────────────────────────────────────────────────────

// newFixtureWithAudit creates a fixture wired to an auditSink so that audit
// events fired from goroutines can be captured and asserted on.
func newFixtureWithAudit(t *testing.T) (*fixture, *auditSink) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	uRepo := &mockUserRepo{}
	sRepo := &mockSessionRepo{}
	jwtMgr := jwtlib.New(testJWTSecret, 15*time.Minute)
	sink := newAuditSink()

	svc := auth.New(uRepo, sRepo, jwtMgr, redisClient, sink, nil, slog.Default(), testRefreshTTL)

	return &fixture{
		svc:     svc,
		uRepo:   uRepo,
		sRepo:   sRepo,
		jwtMgr:  jwtMgr,
		miniRed: mr,
	}, sink
}

func TestLogin_Success_AuditEventLogged(t *testing.T) {
	t.Parallel()
	f, sink := newFixtureWithAudit(t)
	user := fakeUser(t)

	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)

	_, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
	})
	require.NoError(t, err)

	e := sink.next(t)
	assert.Equal(t, auditRepo.EventLoginSuccess, e.EventType)
	require.NotNil(t, e.UserID)
	assert.Equal(t, user.ID, *e.UserID)
}

func TestLogin_Failure_AuditEventLogged(t *testing.T) {
	t.Parallel()
	f, sink := newFixtureWithAudit(t)
	user := fakeUser(t)

	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)

	_, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "wrong-password",
	})
	require.Error(t, err)

	e := sink.next(t)
	assert.Equal(t, auditRepo.EventLoginFailure, e.EventType)
}

func TestRegister_AuditEventLogged(t *testing.T) {
	t.Parallel()
	f, sink := newFixtureWithAudit(t)

	f.uRepo.On("Create", mock.Anything, "alice@example.com", mock.AnythingOfType("string")).
		Return(&models.User{ID: "user-001", Email: "alice@example.com"}, nil)

	_, err := f.svc.Register(context.Background(), &api.RegisterRequest{
		Email:    "alice@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	e := sink.next(t)
	assert.Equal(t, auditRepo.EventRegister, e.EventType)
	require.NotNil(t, e.UserID)
	assert.Equal(t, "user-001", *e.UserID)
}

func TestLogout_AuditEventLogged(t *testing.T) {
	t.Parallel()
	f, sink := newFixtureWithAudit(t)
	user := fakeUser(t)

	// Login to populate the Redis session cache.
	f.uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)
	f.sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)

	loginResp, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
	})
	require.NoError(t, err)
	_ = sink.next(t) // consume the login audit event

	// Logout using the refresh token from the login response — no Bearer token required.
	hashedToken := token.Hash(loginResp.RefreshToken)
	f.sRepo.On("DeleteByTokenHash", mock.Anything, hashedToken).Return(nil)

	_, err = f.svc.Logout(context.Background(), &api.LogoutRequest{
		RefreshToken: loginResp.RefreshToken,
	})
	require.NoError(t, err)

	e := sink.next(t)
	assert.Equal(t, auditRepo.EventLogout, e.EventType)
	assert.Nil(t, e.UserID, "Logout is unauthenticated — no userID in audit event")
}

// ── Internal error paths ───────────────────────────────────────────────────────

func TestLogin_InternalError_GetByEmail(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	f.uRepo.On("GetByEmail", mock.Anything, "alice@example.com").
		Return((*models.User)(nil), fmt.Errorf("db connection lost"))

	_, err := f.svc.Login(context.Background(), &api.LoginRequest{
		Email:    "alice@example.com",
		Password: "password123",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestLogout_InternalError(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctx := f.ctxWithBearerToken(t, "user-001", "alice@example.com")
	plainToken, hashedToken, _ := token.Generate()
	f.sRepo.On("DeleteByTokenHash", mock.Anything, hashedToken).
		Return(fmt.Errorf("db error"))

	_, err := f.svc.Logout(ctx, &api.LogoutRequest{RefreshToken: plainToken})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestRefreshToken_InternalError_RotateSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	plainToken, hashedToken, _ := token.Generate()
	dbSession := &models.Session{
		ID:        "sess-001",
		UserID:    "user-001",
		UserEmail: "alice@example.com",
		TokenHash: hashedToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	f.sRepo.On("GetByTokenHash", mock.Anything, hashedToken).Return(dbSession, nil)
	f.sRepo.On("RotateToken", mock.Anything, hashedToken, mock.AnythingOfType("*models.Session")).
		Return(fmt.Errorf("db error"))

	_, err := f.svc.RefreshToken(context.Background(), &api.RefreshTokenRequest{RefreshToken: plainToken})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestRefreshToken_ConcurrentReplay_ReturnsUnauthenticated(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	plainToken, hashedToken, _ := token.Generate()
	dbSession := &models.Session{
		ID:        "sess-001",
		UserID:    "user-001",
		UserEmail: "alice@example.com",
		TokenHash: hashedToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	f.sRepo.On("GetByTokenHash", mock.Anything, hashedToken).Return(dbSession, nil)
	// Simulates concurrent rotation: the token was already consumed by another request.
	f.sRepo.On("RotateToken", mock.Anything, hashedToken, mock.AnythingOfType("*models.Session")).
		Return(sessionRepo.ErrNotFound)

	_, err := f.svc.RefreshToken(context.Background(), &api.RefreshTokenRequest{RefreshToken: plainToken})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestLogoutAll_InternalError(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctx := f.ctxWithBearerToken(t, "user-001", "alice@example.com")
	f.sRepo.On("DeleteAllByUserID", mock.Anything, "user-001").
		Return([]string(nil), fmt.Errorf("db error"))

	_, err := f.svc.LogoutAll(ctx, &api.LogoutAllRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestListSessions_InternalError(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctx := f.ctxWithBearerToken(t, "user-001", "alice@example.com")
	f.sRepo.On("ListByUserID", mock.Anything, "user-001").
		Return(([]*models.Session)(nil), fmt.Errorf("db error"))

	_, err := f.svc.ListSessions(ctx, &api.ListSessionsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestRevokeSession_InternalError(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctx := f.ctxWithBearerToken(t, "user-001", "alice@example.com")
	f.sRepo.On("DeleteByID", mock.Anything, "sess-001", "user-001").
		Return("", fmt.Errorf("db error"))

	_, err := f.svc.RevokeSession(ctx, &api.RevokeSessionRequest{SessionId: "sess-001"})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ── cacheSession TTL≤0 ────────────────────────────────────────────────────────

// TestLogin_ExpiredRefreshTTL_NotCached verifies that cacheSession skips writing
// to Redis when the computed TTL is non-positive (session already expired).
func TestLogin_ExpiredRefreshTTL_NotCached(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })

	uRepo := &mockUserRepo{}
	sRepo := &mockSessionRepo{}
	jwtMgr := jwtlib.New(testJWTSecret, 15*time.Minute)
	// Negative TTL → sessions expire instantly → cacheSession must skip Set.
	svc := auth.New(uRepo, sRepo, jwtMgr, rc, nil, nil, slog.Default(), -time.Hour)

	user := fakeUser(t)
	uRepo.On("GetByEmail", mock.Anything, user.Email).Return(user, nil)
	sRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Session")).Return(nil)

	resp, err := svc.Login(context.Background(), &api.LoginRequest{
		Email:    user.Email,
		Password: "password123",
	})
	require.NoError(t, err)

	tokenHash := token.Hash(resp.RefreshToken)
	assert.False(t, mr.Exists("refresh:"+tokenHash), "session with non-positive TTL must not be cached")
}
