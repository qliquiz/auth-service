package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"auth-service/internal/config"

	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret-must-be-at-least-32-chars!!"

func TestBuildTokenManager_HS256(t *testing.T) {
	t.Parallel()
	cfg := config.JWTConfig{Algorithm: "hs256", Secret: testSecret, AccessTTL: 15 * time.Minute}
	mgr, err := buildTokenManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	tok, err := mgr.GenerateAccessToken("uid", "u@e.com", nil)
	require.NoError(t, err)
	claims, err := mgr.ValidateAccessToken(tok)
	require.NoError(t, err)
	require.Equal(t, "uid", claims.UserID)
}

func TestBuildTokenManager_EmptyAlgorithmDefaultsToHS256(t *testing.T) {
	t.Parallel()
	cfg := config.JWTConfig{Algorithm: "", Secret: testSecret, AccessTTL: 15 * time.Minute}
	mgr, err := buildTokenManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, mgr)
}

func TestBuildTokenManager_RS256(t *testing.T) {
	t.Parallel()
	path := writeRSAKey(t)
	cfg := config.JWTConfig{Algorithm: "rs256", PrivateKeyPath: path, AccessTTL: 15 * time.Minute}
	mgr, err := buildTokenManager(cfg)
	require.NoError(t, err)

	tok, err := mgr.GenerateAccessToken("uid", "u@e.com", nil)
	require.NoError(t, err)
	_, err = mgr.ValidateAccessToken(tok)
	require.NoError(t, err)
}

func TestBuildTokenManager_ES256(t *testing.T) {
	t.Parallel()
	path := writeECDSAKey(t)
	cfg := config.JWTConfig{Algorithm: "es256", PrivateKeyPath: path, AccessTTL: 15 * time.Minute}
	mgr, err := buildTokenManager(cfg)
	require.NoError(t, err)

	tok, err := mgr.GenerateAccessToken("uid", "u@e.com", nil)
	require.NoError(t, err)
	_, err = mgr.ValidateAccessToken(tok)
	require.NoError(t, err)
}

func TestBuildTokenManager_RS256_MissingFile(t *testing.T) {
	t.Parallel()
	cfg := config.JWTConfig{Algorithm: "rs256", PrivateKeyPath: "/no/such/file.pem", AccessTTL: 15 * time.Minute}
	_, err := buildTokenManager(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "read RSA key")
}

func TestBuildTokenManager_ES256_MissingFile(t *testing.T) {
	t.Parallel()
	cfg := config.JWTConfig{Algorithm: "es256", PrivateKeyPath: "/no/such/file.pem", AccessTTL: 15 * time.Minute}
	_, err := buildTokenManager(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "read ECDSA key")
}

func TestBuildTokenManager_RS256_WrongKeyType(t *testing.T) {
	t.Parallel()
	// Provide an ECDSA key where RSA is expected.
	path := writeECDSAKey(t)
	cfg := config.JWTConfig{Algorithm: "rs256", PrivateKeyPath: path, AccessTTL: 15 * time.Minute}
	_, err := buildTokenManager(cfg)
	require.Error(t, err)
}

func TestBuildTokenManager_ES256_WrongKeyType(t *testing.T) {
	t.Parallel()
	// Provide an RSA key where ECDSA is expected.
	path := writeRSAKey(t)
	cfg := config.JWTConfig{Algorithm: "es256", PrivateKeyPath: path, AccessTTL: 15 * time.Minute}
	_, err := buildTokenManager(cfg)
	require.Error(t, err)
}

func TestBuildTokenManager_UnknownAlgorithm(t *testing.T) {
	t.Parallel()
	cfg := config.JWTConfig{Algorithm: "rsa512", Secret: testSecret, AccessTTL: 15 * time.Minute}
	_, err := buildTokenManager(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported JWT_ALGORITHM")
}

// ── helpers ───────────────────────────────────────────────────────────────────

func writeRSAKey(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return writePEM(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))
}

func writeECDSAKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return writePEM(t, "EC PRIVATE KEY", der)
}

func writePEM(t *testing.T, keyType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: keyType, Bytes: der}))
	return path
}
