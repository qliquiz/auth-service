package memory_test

import (
	"context"
	"testing"

	userRepo "auth-service/internal/repository/user"
	"auth-service/pkg/storage/memory"

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
	require.ErrorIs(t, err, userRepo.ErrAlreadyExists)
}

func TestMemoryUserStore_NotFound(t *testing.T) {
	t.Parallel()
	store := memory.NewUserStore()
	ctx := context.Background()

	_, err := store.GetByEmail(ctx, "nobody@example.com")
	require.ErrorIs(t, err, userRepo.ErrNotFound)

	_, err = store.GetByID(ctx, "no-such-id")
	require.ErrorIs(t, err, userRepo.ErrNotFound)
}
