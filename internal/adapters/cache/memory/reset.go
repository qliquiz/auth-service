package memory

import (
	"context"
	"sync"
	"time"

	"auth-service/internal/domain/ports"
	"auth-service/internal/lib/token"
)

var _ ports.PasswordResetStore = (*ResetStore)(nil)

type otpEntry struct {
	record    ports.OTPRecord
	expiresAt time.Time
}

type resetTokenEntry struct {
	record    ports.ResetTokenRecord
	expiresAt time.Time
}

type ResetStore struct {
	mu          sync.Mutex
	otps        map[string]otpEntry        // key: sha256(email)
	resetTokens map[string]resetTokenEntry // key: sha256(token)
}

func NewResetStore() *ResetStore {
	return &ResetStore{
		otps:        make(map[string]otpEntry),
		resetTokens: make(map[string]resetTokenEntry),
	}
}

func (s *ResetStore) SaveOTP(_ context.Context, userID, email, otpHash string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.otps[token.Hash(email)] = otpEntry{
		record:    ports.OTPRecord{UserID: userID, OTPHash: otpHash, Attempts: 0},
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *ResetStore) GetOTP(_ context.Context, email string) (*ports.OTPRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.otps[token.Hash(email)]
	if !ok || time.Now().After(e.expiresAt) {
		delete(s.otps, token.Hash(email))
		return nil, ports.ErrResetCodeNotFound
	}
	cp := e.record
	return &cp, nil
}

func (s *ResetStore) IncrOTPAttempts(_ context.Context, email string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := token.Hash(email)
	e, ok := s.otps[k]
	if !ok || time.Now().After(e.expiresAt) {
		delete(s.otps, k)
		return 0, ports.ErrResetCodeNotFound
	}
	e.record.Attempts++
	s.otps[k] = e
	return e.record.Attempts, nil
}

func (s *ResetStore) DeleteOTP(_ context.Context, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.otps, token.Hash(email))
	return nil
}

func (s *ResetStore) SaveResetToken(_ context.Context, tokenHash, userID, email string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetTokens[tokenHash] = resetTokenEntry{
		record:    ports.ResetTokenRecord{UserID: userID, Email: email},
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *ResetStore) GetResetToken(_ context.Context, tokenHash string) (*ports.ResetTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.resetTokens[tokenHash]
	if !ok || time.Now().After(e.expiresAt) {
		delete(s.resetTokens, tokenHash)
		return nil, ports.ErrResetTokenNotFound
	}
	cp := e.record
	return &cp, nil
}

func (s *ResetStore) DeleteResetToken(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.resetTokens, tokenHash)
	return nil
}
