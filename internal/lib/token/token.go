package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Generate creates a cryptographically random token.
// Returns the plaintext token (sent to client) and its SHA-256 hash (stored in DB/Redis).
func Generate() (plain, hashed string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate random bytes: %w", err)
	}
	plain = base64.URLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(plain))
	hashed = hex.EncodeToString(h[:])
	return plain, hashed, nil
}

// Hash returns the SHA-256 hex digest of the given plaintext token.
func Hash(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}
