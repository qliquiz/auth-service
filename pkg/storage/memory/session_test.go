package memory_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"auth-service/internal/domain/models"
	sessionRepo "auth-service/internal/repository/session"
	"auth-service/pkg/storage/memory"

	"github.com/stretchr/testify/require"
)

func TestMemorySessionStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	sess := &models.Session{
		UserID:    "uid-1",
		TokenHash: "hash-abc",
		DeviceID:  "device-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, store.Create(ctx, sess))
	require.NotEmpty(t, sess.ID)

	got, err := store.GetByTokenHash(ctx, "hash-abc")
	require.NoError(t, err)
	require.Equal(t, sess.ID, got.ID)
	require.Equal(t, "uid-1", got.UserID)
}

func TestMemorySessionStore_RotateToken(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	old := &models.Session{UserID: "uid-1", TokenHash: "old-hash", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.Create(ctx, old))

	newSess := &models.Session{UserID: "uid-1", TokenHash: "new-hash", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.RotateToken(ctx, "old-hash", newSess))

	_, err := store.GetByTokenHash(ctx, "old-hash")
	require.ErrorIs(t, err, sessionRepo.ErrNotFound, "old token must be gone")

	got, err := store.GetByTokenHash(ctx, "new-hash")
	require.NoError(t, err)
	require.Equal(t, newSess.ID, got.ID)
}

func TestMemorySessionStore_ConcurrentReplay(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	sess := &models.Session{UserID: "uid-1", TokenHash: "replay-hash", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.Create(ctx, sess))

	newSess1 := &models.Session{UserID: "uid-1", TokenHash: "new-1", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.RotateToken(ctx, "replay-hash", newSess1))

	// Second rotation of the same old hash must fail.
	newSess2 := &models.Session{UserID: "uid-1", TokenHash: "new-2", ExpiresAt: time.Now().Add(time.Hour)}
	err := store.RotateToken(ctx, "replay-hash", newSess2)
	require.ErrorIs(t, err, sessionRepo.ErrNotFound)
}

func TestMemorySessionStore_DeleteByID_WrongUser(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	sess := &models.Session{UserID: "uid-1", TokenHash: "hash-x", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.Create(ctx, sess))

	_, err := store.DeleteByID(ctx, sess.ID, "uid-WRONG")
	require.ErrorIs(t, err, sessionRepo.ErrNotFound)
}

func TestMemorySessionStore_DeleteAllByUserID(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		s := &models.Session{
			UserID:    "uid-multi",
			TokenHash: fmt.Sprintf("hash-%d", i),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		require.NoError(t, store.Create(ctx, s))
	}

	hashes, err := store.DeleteAllByUserID(ctx, "uid-multi")
	require.NoError(t, err)
	require.Len(t, hashes, 3)

	sessions, err := store.ListByUserID(ctx, "uid-multi")
	require.NoError(t, err)
	require.Empty(t, sessions)
}
