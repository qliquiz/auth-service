package memory_test

import (
	"context"
	"testing"
	"time"

	memcache "auth-service/pkg/cache/memory"
	"auth-service/pkg/ports"

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
	require.Error(t, err, "should be cache miss after delete")
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
	ctx := context.Background()

	// Delete on a non-existent key must not return an error (idempotent).
	require.NoError(t, cache.Delete(ctx, "nonexistent"))
}
