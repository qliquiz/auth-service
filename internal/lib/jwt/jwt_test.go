package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	jwtlib "auth-service/internal/lib/jwt"

	jwtpkg "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret-must-be-at-least-32-chars!!"

func TestManager_GenerateAndValidate(t *testing.T) {
	t.Parallel()

	m := jwtlib.New(testSecret, 15*time.Minute)

	token, err := m.GenerateAccessToken("user-123", "alice@example.com", []string{"user", "admin"})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := m.ValidateAccessToken(token)
	require.NoError(t, err)

	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "alice@example.com", claims.Email)
	assert.Equal(t, []string{"user", "admin"}, claims.Roles)
}

func TestManager_EmptyRoles(t *testing.T) {
	t.Parallel()

	m := jwtlib.New(testSecret, time.Hour)

	token, err := m.GenerateAccessToken("user-456", "bob@example.com", nil)
	require.NoError(t, err)

	claims, err := m.ValidateAccessToken(token)
	require.NoError(t, err)
	assert.Empty(t, claims.Roles)
}

func TestManager_ExpiredToken(t *testing.T) {
	t.Parallel()

	m := jwtlib.New(testSecret, -time.Second) // TTL in the past → already expired

	token, err := m.GenerateAccessToken("user-123", "alice@example.com", nil)
	require.NoError(t, err)

	_, err = m.ValidateAccessToken(token)
	assert.Error(t, err, "expired token must be rejected")
}

func TestManager_WrongSecret(t *testing.T) {
	t.Parallel()

	signer := jwtlib.New("secret-aaaaaaaaaaaaaaaaaaaaaaaaaaa", time.Hour)
	verifier := jwtlib.New("secret-bbbbbbbbbbbbbbbbbbbbbbbbbbb", time.Hour)

	token, err := signer.GenerateAccessToken("user-123", "test@example.com", nil)
	require.NoError(t, err)

	_, err = verifier.ValidateAccessToken(token)
	assert.Error(t, err, "token signed with a different secret must be rejected")
}

func TestManager_MalformedToken(t *testing.T) {
	t.Parallel()

	m := jwtlib.New(testSecret, time.Hour)

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

	m := jwtlib.New(testSecret, time.Hour)
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

	m := jwtlib.New(testSecret, time.Hour)
	_, err = m.ValidateAccessToken(tokenStr)
	assert.Error(t, err, "token with wrong issuer must be rejected")
}

func TestManager_TokenNotExpiredYet(t *testing.T) {
	t.Parallel()

	m := jwtlib.New(testSecret, 24*time.Hour)

	token, err := m.GenerateAccessToken("user-789", "charlie@example.com", []string{"user"})
	require.NoError(t, err)

	claims, err := m.ValidateAccessToken(token)
	require.NoError(t, err)
	assert.NotEmpty(t, claims.UserID)
}

func TestRS256RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mgr := jwtlib.NewRS256Manager(priv, 15*time.Minute)

	token, err := mgr.GenerateAccessToken("uid-1", "user@example.com", []string{"user"})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := mgr.ValidateAccessToken(token)
	require.NoError(t, err)
	require.Equal(t, "uid-1", claims.UserID)
	require.Equal(t, "user@example.com", claims.Email)
	require.Equal(t, []string{"user"}, claims.Roles)
}

func TestRS256RejectsExpired(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mgr := jwtlib.NewRS256Manager(priv, -1*time.Second)

	token, err := mgr.GenerateAccessToken("uid-1", "u@e.com", nil)
	require.NoError(t, err)

	_, err = mgr.ValidateAccessToken(token)
	require.Error(t, err)
}

func TestES256RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mgr := jwtlib.NewES256Manager(priv, 15*time.Minute)

	token, err := mgr.GenerateAccessToken("uid-2", "ec@example.com", []string{"admin"})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := mgr.ValidateAccessToken(token)
	require.NoError(t, err)
	require.Equal(t, "uid-2", claims.UserID)
	require.Equal(t, []string{"admin"}, claims.Roles)
}
