package memory_test

import (
	"context"
	"testing"

	"auth-service/internal/adapters/storage/memory"
	"auth-service/internal/domain/ports"

	"github.com/stretchr/testify/require"
)

func TestMemoryUserStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	store := memory.NewUserStore()
	ctx := context.Background()

	user, err := store.Create(ctx, "alice@example.com", "hash1")
	require.NoError(t, err)
	require.NotEmpty(t, user.ID)
	require.Equal(t, "alice@example.com", user.Email)
	require.Equal(t, "hash1", user.PasswordHash)

	gotByEmail, err := store.GetByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, user.ID, gotByEmail.ID)

	gotByID, err := store.GetByID(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, user.ID, gotByID.ID)
}

func TestMemoryUserStore_DuplicateEmail(t *testing.T) {
	t.Parallel()
	store := memory.NewUserStore()
	ctx := context.Background()

	_, err := store.Create(ctx, "bob@example.com", "hash1")
	require.NoError(t, err)

	_, err = store.Create(ctx, "bob@example.com", "hash2")
	require.ErrorIs(t, err, ports.ErrUserAlreadyExists)
}

func TestMemoryUserStore_NotFound(t *testing.T) {
	t.Parallel()
	store := memory.NewUserStore()
	ctx := context.Background()

	_, err := store.GetByEmail(ctx, "nobody@example.com")
	require.ErrorIs(t, err, ports.ErrUserNotFound)

	_, err = store.GetByID(ctx, "no-such-id")
	require.ErrorIs(t, err, ports.ErrUserNotFound)
}

func TestMemoryUserStore_GetReturnsCopy(t *testing.T) {
	t.Parallel()
	store := memory.NewUserStore()
	ctx := context.Background()

	_, err := store.Create(ctx, "carol@example.com", "hash1")
	require.NoError(t, err)

	u1, err := store.GetByEmail(ctx, "carol@example.com")
	require.NoError(t, err)
	u1.Email = "mutated"

	u2, err := store.GetByEmail(ctx, "carol@example.com")
	require.NoError(t, err)
	require.Equal(t, "carol@example.com", u2.Email, "store must return independent copies")
}
