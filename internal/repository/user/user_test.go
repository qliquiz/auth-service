//go:build integration

package user_test

import (
	"context"
	"log"
	"os"
	"testing"

	"auth-service/internal/repository/testutil"
	"auth-service/internal/repository/user"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sharedPool *pgxpool.Pool

func TestMain(m *testing.M) {
	suite, err := testutil.NewSuite()
	if err != nil {
		log.Fatalf("setup postgres: %v", err)
	}
	sharedPool = suite.Pool

	code := m.Run()

	suite.Teardown()
	os.Exit(code)
}

func TestUserRepository_Create(t *testing.T) {
	t.Parallel()
	repo := user.New(sharedPool)
	ctx := context.Background()

	u, err := repo.Create(ctx, "alice@example.com", "hashed_password")
	require.NoError(t, err)

	assert.NotEmpty(t, u.ID)
	assert.Equal(t, "alice@example.com", u.Email)
	assert.Equal(t, "hashed_password", u.PasswordHash)
	assert.False(t, u.CreatedAt.IsZero())
	assert.False(t, u.UpdatedAt.IsZero())
}

func TestUserRepository_Create_DuplicateEmail(t *testing.T) {
	t.Parallel()
	repo := user.New(sharedPool)
	ctx := context.Background()

	_, err := repo.Create(ctx, "dup@example.com", "hash1")
	require.NoError(t, err)

	_, err = repo.Create(ctx, "dup@example.com", "hash2")
	require.Error(t, err)
	assert.ErrorIs(t, err, user.ErrAlreadyExists)
}

func TestUserRepository_GetByEmail_Found(t *testing.T) {
	t.Parallel()
	repo := user.New(sharedPool)
	ctx := context.Background()

	created, err := repo.Create(ctx, "bob@example.com", "bobhash")
	require.NoError(t, err)

	found, err := repo.GetByEmail(ctx, "bob@example.com")
	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, created.Email, found.Email)
}

func TestUserRepository_GetByEmail_NotFound(t *testing.T) {
	t.Parallel()
	repo := user.New(sharedPool)
	ctx := context.Background()

	_, err := repo.GetByEmail(ctx, "nobody@example.com")
	require.Error(t, err)
	assert.ErrorIs(t, err, user.ErrNotFound)
}

func TestUserRepository_GetByID_Found(t *testing.T) {
	t.Parallel()
	repo := user.New(sharedPool)
	ctx := context.Background()

	created, err := repo.Create(ctx, "carol@example.com", "carolhash")
	require.NoError(t, err)

	found, err := repo.GetByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "carol@example.com", found.Email)
}

func TestUserRepository_GetByID_NotFound(t *testing.T) {
	t.Parallel()
	repo := user.New(sharedPool)
	ctx := context.Background()

	_, err := repo.GetByID(ctx, "00000000-0000-0000-0000-000000000000")
	require.Error(t, err)
	assert.ErrorIs(t, err, user.ErrNotFound)
}
