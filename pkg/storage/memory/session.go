package memory

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/domain/models"
	sessionRepo "auth-service/internal/repository/session"
	"auth-service/pkg/ports"
)

// Compile-time assertion: SessionStore must implement ports.SessionStore.
var _ ports.SessionStore = (*SessionStore)(nil)

// SessionStore is a thread-safe, in-memory implementation of ports.SessionStore.
type SessionStore struct {
	mu     sync.Mutex
	byID   map[string]*models.Session
	byHash map[string]*models.Session // tokenHash → Session
}

// NewSessionStore creates an empty SessionStore.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		byID:   make(map[string]*models.Session),
		byHash: make(map[string]*models.Session),
	}
}

func (s *SessionStore) Create(_ context.Context, sess *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.ID == "" {
		sess.ID = uuid.NewString()
	}
	now := time.Now()
	sess.CreatedAt = now
	sess.LastUsedAt = now
	cp := *sess
	s.byID[sess.ID] = &cp
	s.byHash[sess.TokenHash] = &cp
	return nil
}

func (s *SessionStore) GetByTokenHash(_ context.Context, tokenHash string) (*models.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byHash[tokenHash]
	if !ok {
		return nil, sessionRepo.ErrNotFound
	}
	sess.LastUsedAt = time.Now()
	cp := *sess
	return &cp, nil
}

func (s *SessionStore) DeleteByID(_ context.Context, sessionID, userID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[sessionID]
	if !ok || sess.UserID != userID {
		return "", sessionRepo.ErrNotFound
	}
	hash := sess.TokenHash
	delete(s.byID, sessionID)
	delete(s.byHash, hash)
	return hash, nil
}

func (s *SessionStore) DeleteByTokenHash(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byHash[tokenHash]
	if !ok {
		return sessionRepo.ErrNotFound
	}
	delete(s.byID, sess.ID)
	delete(s.byHash, tokenHash)
	return nil
}

// RotateToken atomically replaces the session identified by oldHash with
// newSess. Returns sessionRepo.ErrNotFound if oldHash is absent — the caller
// treats this as a concurrent replay attempt.
func (s *SessionStore) RotateToken(_ context.Context, oldHash string, newSess *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.byHash[oldHash]
	if !ok {
		return sessionRepo.ErrNotFound
	}
	delete(s.byID, old.ID)
	delete(s.byHash, oldHash)

	if newSess.ID == "" {
		newSess.ID = uuid.NewString()
	}
	now := time.Now()
	newSess.CreatedAt = now
	newSess.LastUsedAt = now
	cp := *newSess
	s.byID[newSess.ID] = &cp
	s.byHash[newSess.TokenHash] = &cp
	return nil
}

func (s *SessionStore) DeleteAllByUserID(_ context.Context, userID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var hashes []string
	for id, sess := range s.byID {
		if sess.UserID == userID {
			hashes = append(hashes, sess.TokenHash)
			delete(s.byHash, sess.TokenHash)
			delete(s.byID, id)
		}
	}
	return hashes, nil
}

func (s *SessionStore) ListByUserID(_ context.Context, userID string) ([]*models.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*models.Session
	for _, sess := range s.byID {
		if sess.UserID == userID {
			cp := *sess
			result = append(result, &cp)
		}
	}
	return result, nil
}
