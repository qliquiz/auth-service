package interceptor_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"auth-service/internal/interceptor"
	"auth-service/internal/lib/ratelimit"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// okHandler is a gRPC handler stub that always succeeds.
func okHandler(_ context.Context, req any) (any, error) { return req, nil }

// infoFor builds a UnaryServerInfo for the given RPC name.
func infoFor(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: "/api.AuthService/" + method}
}

// ctxWithIP creates a gRPC incoming context carrying an X-Forwarded-For header.
func ctxWithIP(ip string) context.Context {
	md := metadata.Pairs("x-forwarded-for", ip)
	return metadata.NewIncomingContext(context.Background(), md)
}

// newRateLimitMW is a test helper that returns an interceptor backed by a fresh
// miniredis instance.
func newRateLimitMW(t *testing.T, globalRPM, loginRPM int) grpc.UnaryServerInterceptor {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })

	global := ratelimit.New(rc, globalRPM, time.Minute)
	login := ratelimit.New(rc, loginRPM, time.Minute)
	return interceptor.RateLimit(global, login, slog.Default())
}

func TestRateLimit_AllowsWithinLimit(t *testing.T) {
	t.Parallel()
	mw := newRateLimitMW(t, 10, 10)
	ctx := ctxWithIP("1.2.3.4")

	for i := range 5 {
		_, err := mw(ctx, nil, infoFor("ValidateToken"), okHandler)
		require.NoError(t, err, "request %d should pass", i+1)
	}
}

func TestRateLimit_GlobalLimitBlocks(t *testing.T) {
	t.Parallel()
	mw := newRateLimitMW(t, 2, 100)
	ctx := ctxWithIP("1.2.3.4")

	_, err := mw(ctx, nil, infoFor("ValidateToken"), okHandler)
	require.NoError(t, err)
	_, err = mw(ctx, nil, infoFor("ValidateToken"), okHandler)
	require.NoError(t, err)

	_, err = mw(ctx, nil, infoFor("ValidateToken"), okHandler)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestRateLimit_LoginLimitBlocks(t *testing.T) {
	t.Parallel()
	// High global limit so it never fires; tight login limit.
	mw := newRateLimitMW(t, 100, 2)
	ctx := ctxWithIP("1.2.3.4")

	_, err := mw(ctx, nil, infoFor("Login"), okHandler)
	require.NoError(t, err)
	_, err = mw(ctx, nil, infoFor("Login"), okHandler)
	require.NoError(t, err)

	// Third Login request exceeds the per-IP login limit.
	_, err = mw(ctx, nil, infoFor("Login"), okHandler)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

// TestRateLimit_LoginLimitDoesNotApplyToOtherMethods ensures that the stricter
// login limiter is only checked for Login and Register, not for other methods.
func TestRateLimit_LoginLimitDoesNotApplyToOtherMethods(t *testing.T) {
	t.Parallel()
	// Login limit is 1 — would block on the 2nd call if applied to ValidateToken.
	mw := newRateLimitMW(t, 100, 1)
	ctx := ctxWithIP("1.2.3.4")

	for i := range 5 {
		_, err := mw(ctx, nil, infoFor("ValidateToken"), okHandler)
		require.NoError(t, err, "ValidateToken request %d must not be blocked by login limiter", i+1)
	}
}

// TestRateLimit_IsolatesIPs verifies that counters are per-IP — one IP being
// rate-limited does not affect another IP.
func TestRateLimit_IsolatesIPs(t *testing.T) {
	t.Parallel()
	mw := newRateLimitMW(t, 2, 100)

	// Exhaust limit for 1.2.3.4.
	ctx1 := ctxWithIP("1.2.3.4")
	_, _ = mw(ctx1, nil, infoFor("ValidateToken"), okHandler)
	_, _ = mw(ctx1, nil, infoFor("ValidateToken"), okHandler)
	_, err := mw(ctx1, nil, infoFor("ValidateToken"), okHandler)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	// A different IP should still be allowed.
	ctx2 := ctxWithIP("9.9.9.9")
	_, err = mw(ctx2, nil, infoFor("ValidateToken"), okHandler)
	require.NoError(t, err, "different IP must not be affected by another IP's rate limit")
}

// TestRateLimit_FailsOpenOnRedisError verifies that when Redis is unavailable the
// interceptor lets requests through rather than blocking all traffic.
func TestRateLimit_FailsOpenOnRedisError(t *testing.T) {
	t.Parallel()
	mr, err := miniredis.Run()
	require.NoError(t, err)

	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })

	global := ratelimit.New(rc, 2, time.Minute)
	login := ratelimit.New(rc, 2, time.Minute)
	mw := interceptor.RateLimit(global, login, slog.Default())

	mr.Close() // simulate Redis outage

	ctx := ctxWithIP("1.2.3.4")
	_, err = mw(ctx, nil, infoFor("Login"), okHandler)
	require.NoError(t, err, "interceptor must fail open when Redis is unavailable")
}
