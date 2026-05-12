package otp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Generate returns a cryptographically random 6-digit numeric OTP string (e.g. "047291").
func Generate() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}
	n := binary.BigEndian.Uint32(b[:]) % 1_000_000
	return fmt.Sprintf("%06d", n), nil
}
