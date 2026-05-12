package memory_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"auth-service/internal/adapters/storage/memory"
	"auth-service/internal/domain/models"
	"auth-service/internal/domain/ports"

	"github.com/stretchr/testify/require"
)

func newSession(userID, tokenHash string) *models.Session {
	return &models.Session{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestMemorySessionStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	sess := newSession("uid-1", "hash-abc")
	require.NoError(t, store.Create(ctx, sess))
	require.NotEmpty(t, sess.ID)

	got, err := store.GetByTokenHash(ctx, "hash-abc")
	require.NoError(t, err)
	require.Equal(t, sess.ID, got.ID)
	require.Equal(t, "uid-1", got.UserID)
}

func TestMemorySessionStore_GetUpdatesLastUsedAt(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	sess := newSession("uid-1", "hash-lu")
	require.NoError(t, store.Create(ctx, sess))

	before := time.Now()
	got, err := store.GetByTokenHash(ctx, "hash-lu")
	require.NoError(t, err)
	require.True(t, got.LastUsedAt.After(before) || got.LastUsedAt.Equal(before),
		"LastUsedAt must be updated on Get")
}

func TestMemorySessionStore_GetNotFound(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	_, err := store.GetByTokenHash(context.Background(), "no-such-hash")
	require.ErrorIs(t, err, ports.ErrSessionNotFound)
}

func TestMemorySessionStore_RotateToken(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	old := newSession("uid-1", "old-hash")
	require.NoError(t, store.Create(ctx, old))

	newSess := newSession("uid-1", "new-hash")
	require.NoError(t, store.RotateToken(ctx, "old-hash", newSess))

	_, err := store.GetByTokenHash(ctx, "old-hash")
	require.ErrorIs(t, err, ports.ErrSessionNotFound, "old token must be gone")

	got, err := store.GetByTokenHash(ctx, "new-hash")
	require.NoError(t, err)
	require.Equal(t, newSess.ID, got.ID)
}

func TestMemorySessionStore_ConcurrentReplay(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	sess := newSession("uid-1", "replay-hash")
	require.NoError(t, store.Create(ctx, sess))

	require.NoError(t, store.RotateToken(ctx, "replay-hash", newSession("uid-1", "new-1")))

	err := store.RotateToken(ctx, "replay-hash", newSession("uid-1", "new-2"))
	require.ErrorIs(t, err, ports.ErrSessionNotFound, "second rotation of same old hash must fail")
}

func TestMemorySessionStore_DeleteByTokenHash_Idempotent(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	require.NoError(t, store.DeleteByTokenHash(ctx, "nonexistent"))
}

func TestMemorySessionStore_DeleteByID_WrongUser(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	sess := newSession("uid-1", "hash-x")
	require.NoError(t, store.Create(ctx, sess))

	_, err := store.DeleteByID(ctx, sess.ID, "uid-WRONG")
	require.ErrorIs(t, err, ports.ErrSessionNotFound)

	// Original session must still exist.
	_, err = store.GetByTokenHash(ctx, "hash-x")
	require.NoError(t, err)
}

func TestMemorySessionStore_DeleteAllByUserID(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, store.Create(ctx, newSession("uid-multi", fmt.Sprintf("hash-%d", i))))
	}
	// Another user's session must survive.
	require.NoError(t, store.Create(ctx, newSession("uid-other", "hash-other")))

	hashes, err := store.DeleteAllByUserID(ctx, "uid-multi")
	require.NoError(t, err)
	require.Len(t, hashes, 3)

	sessions, err := store.ListByUserID(ctx, "uid-multi")
	require.NoError(t, err)
	require.Empty(t, sessions)

	// Other user's session must be intact.
	other, err := store.ListByUserID(ctx, "uid-other")
	require.NoError(t, err)
	require.Len(t, other, 1)
}

func TestMemorySessionStore_ListByUserID(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		require.NoError(t, store.Create(ctx, newSession("uid-list", fmt.Sprintf("hash-list-%d", i))))
	}

	result, err := store.ListByUserID(ctx, "uid-list")
	require.NoError(t, err)
	require.Len(t, result, 2)
}

func TestMemorySessionStore_DeleteAllByUserIDExcept_KeepsTarget(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, newSession("uid-keep", "hash-a")))
	require.NoError(t, store.Create(ctx, newSession("uid-keep", "hash-b")))
	require.NoError(t, store.Create(ctx, newSession("uid-keep", "hash-c")))
	// Another user's session must survive.
	require.NoError(t, store.Create(ctx, newSession("uid-other", "hash-other")))

	deleted, err := store.DeleteAllByUserIDExcept(ctx, "uid-keep", "hash-b")
	require.NoError(t, err)
	require.Len(t, deleted, 2)
	require.ElementsMatch(t, []string{"hash-a", "hash-c"}, deleted)

	// hash-b must still exist.
	_, err = store.GetByTokenHash(ctx, "hash-b")
	require.NoError(t, err)

	// hash-a and hash-c must be gone.
	_, err = store.GetByTokenHash(ctx, "hash-a")
	require.ErrorIs(t, err, ports.ErrSessionNotFound)
	_, err = store.GetByTokenHash(ctx, "hash-c")
	require.ErrorIs(t, err, ports.ErrSessionNotFound)

	// Other user's session must be intact.
	other, err := store.ListByUserID(ctx, "uid-other")
	require.NoError(t, err)
	require.Len(t, other, 1)
}

func TestMemorySessionStore_DeleteAllByUserIDExcept_EmptyKeep_DeletesAll(t *testing.T) {
	t.Parallel()
	store := memory.NewSessionStore()
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, newSession("uid-all", "hash-1")))
	require.NoError(t, store.Create(ctx, newSession("uid-all", "hash-2")))

	deleted, err := store.DeleteAllByUserIDExcept(ctx, "uid-all", "")
	require.NoError(t, err)
	require.Len(t, deleted, 2)

	sessions, err := store.ListByUserID(ctx, "uid-all")
	require.NoError(t, err)
	require.Empty(t, sessions)
}
