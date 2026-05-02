package jwt_test

import (
	"testing"
	"time"

	"auth-service/internal/lib/jwt"

	jwtpkg "github.com/golang-jwt/jwt/v5"
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

func TestManager_MissingExpClaim(t *testing.T) {
	t.Parallel()

	// Craft a token with a valid HS256 signature but no exp field.
	// WithExpirationRequired() must reject it.
	secret := []byte(testSecret)
	rawClaims := jwtpkg.MapClaims{
		"uid":   "user-123",
		"email": "alice@example.com",
		"roles": []string{"user"},
		"sub":   "user-123",
		"iss":   "auth-service",
		// deliberately no "exp"
	}
	raw := jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, rawClaims)
	tokenStr, err := raw.SignedString(secret)
	require.NoError(t, err)

	m := jwt.New(testSecret, time.Hour)
	_, err = m.ValidateAccessToken(tokenStr)
	assert.Error(t, err, "token without exp must be rejected")
}

func TestManager_WrongIssuer(t *testing.T) {
	t.Parallel()

	// Sign a token with the correct secret but wrong issuer.
	secret := []byte(testSecret)
	claims := jwtpkg.RegisteredClaims{
		Subject:   "user-123",
		Issuer:    "other-service",
		ExpiresAt: jwtpkg.NewNumericDate(time.Now().Add(time.Hour)),
	}
	raw := jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, claims)
	tokenStr, err := raw.SignedString(secret)
	require.NoError(t, err)

	m := jwt.New(testSecret, time.Hour)
	_, err = m.ValidateAccessToken(tokenStr)
	assert.Error(t, err, "token with wrong issuer must be rejected")
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
