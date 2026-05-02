package redis_test

import (
	"testing"

	rediscache "auth-service/internal/cache/redis"
	"auth-service/pkg/ports"
)

// TestRedisAdapterCompiles verifies the Redis adapter satisfies the interface
// at compile time. No real Redis is needed — this is a compilation guard.
func TestRedisAdapterCompiles(t *testing.T) {
	var _ ports.SessionCache = (*rediscache.Cache)(nil)
}
