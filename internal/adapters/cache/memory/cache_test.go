package memory_test

import (
	"context"
	"testing"
	"time"

	memcache "auth-service/internal/adapters/cache/memory"
	"auth-service/internal/domain/ports"

	"github.com/stretchr/testify/require"
)

func TestMemoryCache_SetGetDelete(t *testing.T) {
	t.Parallel()
	cache := memcache.New()
	ctx := context.Background()

	sess := &ports.CachedSession{
		SessionID: "sid-1",
		UserID:    "uid-1",
		UserEmail: "u@e.com",
		DeviceID:  "dev-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	require.NoError(t, cache.Set(ctx, "hash-1", sess, time.Hour))

	got, err := cache.Get(ctx, "hash-1")
	require.NoError(t, err)
	require.Equal(t, "sid-1", got.SessionID)
	require.Equal(t, "uid-1", got.UserID)

	require.NoError(t, cache.Delete(ctx, "hash-1"))

	_, err = cache.Get(ctx, "hash-1")
	require.Error(t, err, "cache miss after delete")
}

func TestMemoryCache_Expiry(t *testing.T) {
	t.Parallel()
	cache := memcache.New()
	ctx := context.Background()

	sess := &ports.CachedSession{SessionID: "s", UserID: "u", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, cache.Set(ctx, "expiring", sess, 10*time.Millisecond))

	time.Sleep(20 * time.Millisecond)

	_, err := cache.Get(ctx, "expiring")
	require.Error(t, err, "expired entry must not be returned")
}

func TestMemoryCache_DeleteMissingKey(t *testing.T) {
	t.Parallel()
	cache := memcache.New()
	require.NoError(t, cache.Delete(context.Background(), "nonexistent"))
}

func TestMemoryCache_SetCopiesSession(t *testing.T) {
	t.Parallel()
	cache := memcache.New()
	ctx := context.Background()

	sess := &ports.CachedSession{SessionID: "sid", UserID: "uid", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, cache.Set(ctx, "h", sess, time.Hour))

	// Mutate the original after Set — cached value must not change.
	sess.SessionID = "mutated"

	got, err := cache.Get(ctx, "h")
	require.NoError(t, err)
	require.Equal(t, "sid", got.SessionID, "cache must store an independent copy")
}

func TestMemoryCache_GetCopiesSession(t *testing.T) {
	t.Parallel()
	cache := memcache.New()
	ctx := context.Background()

	sess := &ports.CachedSession{SessionID: "sid", UserID: "uid", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, cache.Set(ctx, "h", sess, time.Hour))

	got, err := cache.Get(ctx, "h")
	require.NoError(t, err)

	// Mutate the returned copy — next Get must still return original.
	got.SessionID = "mutated"

	got2, err := cache.Get(ctx, "h")
	require.NoError(t, err)
	require.Equal(t, "sid", got2.SessionID, "Get must return an independent copy")
}
