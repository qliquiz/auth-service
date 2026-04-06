package jwt_test

import (
	"testing"
	"time"

	"auth-service/internal/lib/jwt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret-must-be-at-least-32-chars!!"

func TestManager_GenerateAndValidate(t *testing.T) {
	t.Parallel()

	m := jwt.New(testSecret, 15*time.Minute)

	token, err := m.GenerateAccessToken("user-123", "alice@example.com", []string{"user", "admin"})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := m.ValidateAccessToken(token)
	require.NoError(t, err)

	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "alice@example.com", claims.Email)
	assert.Equal(t, []string{"user", "admin"}, claims.Roles)
	assert.Equal(t, "auth-service", claims.Issuer)
	assert.Equal(t, "user-123", claims.Subject)
}

func TestManager_EmptyRoles(t *testing.T) {
	t.Parallel()

	m := jwt.New(testSecret, time.Hour)

	token, err := m.GenerateAccessToken("user-456", "bob@example.com", nil)
	require.NoError(t, err)

	claims, err := m.ValidateAccessToken(token)
	require.NoError(t, err)
	assert.Empty(t, claims.Roles)
}

func TestManager_ExpiredToken(t *testing.T) {
	t.Parallel()

	m := jwt.New(testSecret, -time.Second) // TTL in the past → already expired

	token, err := m.GenerateAccessToken("user-123", "alice@example.com", nil)
	require.NoError(t, err)

	_, err = m.ValidateAccessToken(token)
	assert.Error(t, err, "expired token must be rejected")
}

func TestManager_WrongSecret(t *testing.T) {
	t.Parallel()

	signer := jwt.New("secret-aaaaaaaaaaaaaaaaaaaaaaaaaaa", time.Hour)
	verifier := jwt.New("secret-bbbbbbbbbbbbbbbbbbbbbbbbbbb", time.Hour)

	token, err := signer.GenerateAccessToken("user-123", "test@example.com", nil)
	require.NoError(t, err)

	_, err = verifier.ValidateAccessToken(token)
	assert.Error(t, err, "token signed with a different secret must be rejected")
}

func TestManager_MalformedToken(t *testing.T) {
	t.Parallel()

	m := jwt.New(testSecret, time.Hour)

	cases := []struct {
		name  string
		token string
	}{
		{"empty string", ""},
		{"random garbage", "thisisnotatoken"},
		{"two parts only", "header.payload"},
		{"tampered signature", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.invalidsig"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := m.ValidateAccessToken(tc.token)
			assert.Error(t, err)
		})
	}
}

func TestManager_TokenNotExpiredYet(t *testing.T) {
	t.Parallel()

	m := jwt.New(testSecret, 24*time.Hour)

	token, err := m.GenerateAccessToken("user-789", "charlie@example.com", []string{"user"})
	require.NoError(t, err)

	claims, err := m.ValidateAccessToken(token)
	require.NoError(t, err)
	assert.True(t, claims.ExpiresAt.After(time.Now()))
}
