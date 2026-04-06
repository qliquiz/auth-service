//go:build integration

package session_test

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"auth-service/internal/domain/models"
	sessionrepo "auth-service/internal/repository/session"
	"auth-service/internal/repository/testutil"
	userrepo "auth-service/internal/repository/user"

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

// createUser inserts a user and returns its ID.
func createUser(t *testing.T, email string) string {
	t.Helper()
	u, err := userrepo.New(sharedPool).Create(context.Background(), email, "hash")
	require.NoError(t, err)
	return u.ID
}

// newSession returns a populated Session for the given user.
func newSession(userID, tokenHash string) *models.Session {
	return &models.Session{
		UserID:    userID,
		TokenHash: tokenHash,
		DeviceID:  "device-001",
		UserAgent: "TestAgent/1.0",
		IPAddress: "127.0.0.1",
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Millisecond),
	}
}

func TestSessionRepository_Create(t *testing.T) {
	t.Parallel()
	repo := sessionrepo.New(sharedPool)
	ctx := context.Background()

	userID := createUser(t, "sess-create@example.com")
	sess := newSession(userID, "hash-create-aaa")

	err := repo.Create(ctx, sess)
	require.NoError(t, err)

	assert.NotEmpty(t, sess.ID)
	assert.False(t, sess.CreatedAt.IsZero())
	assert.False(t, sess.LastUsedAt.IsZero())
}

func TestSessionRepository_GetByTokenHash_Found(t *testing.T) {
	t.Parallel()
	repo := sessionrepo.New(sharedPool)
	ctx := context.Background()

	userID := createUser(t, "sess-get@example.com")
	sess := newSession(userID, "hash-get-bbb")
	require.NoError(t, repo.Create(ctx, sess))

	found, err := repo.GetByTokenHash(ctx, "hash-get-bbb")
	require.NoError(t, err)

	assert.Equal(t, sess.ID, found.ID)
	assert.Equal(t, userID, found.UserID)
	assert.Equal(t, "sess-get@example.com", found.UserEmail)
	assert.Equal(t, "hash-get-bbb", found.TokenHash)
}

func TestSessionRepository_GetByTokenHash_NotFound(t *testing.T) {
	t.Parallel()
	repo := sessionrepo.New(sharedPool)
	ctx := context.Background()

	_, err := repo.GetByTokenHash(ctx, "nonexistent-hash")
	require.Error(t, err)
	assert.ErrorIs(t, err, sessionrepo.ErrNotFound)
}

func TestSessionRepository_DeleteByTokenHash(t *testing.T) {
	t.Parallel()
	repo := sessionrepo.New(sharedPool)
	ctx := context.Background()

	userID := createUser(t, "sess-delhash@example.com")
	sess := newSession(userID, "hash-delhash-ccc")
	require.NoError(t, repo.Create(ctx, sess))

	require.NoError(t, repo.DeleteByTokenHash(ctx, "hash-delhash-ccc"))

	_, err := repo.GetByTokenHash(ctx, "hash-delhash-ccc")
	assert.ErrorIs(t, err, sessionrepo.ErrNotFound)
}

func TestSessionRepository_DeleteByID_Success(t *testing.T) {
	t.Parallel()
	repo := sessionrepo.New(sharedPool)
	ctx := context.Background()

	userID := createUser(t, "sess-delid@example.com")
	sess := newSession(userID, "hash-delid-eee")
	require.NoError(t, repo.Create(ctx, sess))

	_, err := repo.DeleteByID(ctx, sess.ID, userID)
	require.NoError(t, err)

	_, err = repo.GetByTokenHash(ctx, "hash-delid-eee")
	assert.ErrorIs(t, err, sessionrepo.ErrNotFound)
}

func TestSessionRepository_DeleteByID_OwnershipEnforced(t *testing.T) {
	t.Parallel()
	repo := sessionrepo.New(sharedPool)
	ctx := context.Background()

	ownerID := createUser(t, "sess-owner@example.com")
	attackerID := createUser(t, "sess-attacker@example.com")

	sess := newSession(ownerID, "hash-ownership-ddd")
	require.NoError(t, repo.Create(ctx, sess))

	// Attacker tries to delete owner's session.
	_, err := repo.DeleteByID(ctx, sess.ID, attackerID)
	assert.ErrorIs(t, err, sessionrepo.ErrNotFound,
		"deleting another user's session must return ErrNotFound")

	// Session must still exist.
	found, err := repo.GetByTokenHash(ctx, "hash-ownership-ddd")
	require.NoError(t, err)
	assert.Equal(t, sess.ID, found.ID)
}

func TestSessionRepository_DeleteAllByUserID(t *testing.T) {
	t.Parallel()
	repo := sessionrepo.New(sharedPool)
	ctx := context.Background()

	userID := createUser(t, "sess-delall@example.com")

	for i, hash := range []string{"hash-delall-f1", "hash-delall-f2", "hash-delall-f3"} {
		s := newSession(userID, hash)
		s.DeviceID = "device-" + string(rune('A'+i))
		require.NoError(t, repo.Create(ctx, s))
	}

	hashes, err := repo.DeleteAllByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, hashes, 3)

	sessions, err := repo.ListByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestSessionRepository_DeleteAllByUserID_DoesNotTouchOtherUsers(t *testing.T) {
	t.Parallel()
	repo := sessionrepo.New(sharedPool)
	ctx := context.Background()

	user1 := createUser(t, "sess-other1@example.com")
	user2 := createUser(t, "sess-other2@example.com")

	require.NoError(t, repo.Create(ctx, newSession(user1, "hash-other-g1")))
	require.NoError(t, repo.Create(ctx, newSession(user2, "hash-other-g2")))

	_, err := repo.DeleteAllByUserID(ctx, user1)
	require.NoError(t, err)

	// user2's session must survive.
	found, err := repo.GetByTokenHash(ctx, "hash-other-g2")
	require.NoError(t, err)
	assert.Equal(t, user2, found.UserID)
}

func TestSessionRepository_ListByUserID_OrderedByLastUsed(t *testing.T) {
	t.Parallel()
	repo := sessionrepo.New(sharedPool)
	ctx := context.Background()

	userID := createUser(t, "sess-list@example.com")

	for _, hash := range []string{"hash-list-h1", "hash-list-h2", "hash-list-h3"} {
		require.NoError(t, repo.Create(ctx, newSession(userID, hash)))
	}

	sessions, err := repo.ListByUserID(ctx, userID)
	require.NoError(t, err)
	require.Len(t, sessions, 3)

	for i := 1; i < len(sessions); i++ {
		assert.False(t, sessions[i].LastUsedAt.After(sessions[i-1].LastUsedAt),
			"sessions must be ordered by last_used_at DESC")
	}
}

func TestSessionRepository_UserDeletedCascadesSessions(t *testing.T) {
	t.Parallel()
	repo := sessionrepo.New(sharedPool)
	ctx := context.Background()

	userID := createUser(t, "sess-cascade@example.com")
	require.NoError(t, repo.Create(ctx, newSession(userID, "hash-cascade-i1")))

	// Delete the user directly — sessions must cascade.
	_, err := sharedPool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	require.NoError(t, err)

	_, err = repo.GetByTokenHash(ctx, "hash-cascade-i1")
	assert.ErrorIs(t, err, sessionrepo.ErrNotFound,
		"deleting a user must cascade-delete their sessions")
}
