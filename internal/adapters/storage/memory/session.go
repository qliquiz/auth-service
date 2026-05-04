package memory

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/domain/models"
	"auth-service/internal/domain/ports"
)

var _ ports.SessionStore = (*SessionStore)(nil)

// SessionStore uses sync.Mutex (not RWMutex) because GetByTokenHash mutates LastUsedAt.
type SessionStore struct {
	mu     sync.Mutex
	byID   map[string]*models.Session
	byHash map[string]*models.Session
}

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
		return nil, ports.ErrSessionNotFound
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
		return "", ports.ErrSessionNotFound
	}
	hash := sess.TokenHash
	delete(s.byID, sessionID)
	delete(s.byHash, hash)
	return hash, nil
}

func (s *SessionStore) DeleteByTokenHash(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byHash[tokenHash]; ok {
		delete(s.byID, sess.ID)
		delete(s.byHash, tokenHash)
	}
	return nil
}

// RotateToken returns ErrSessionNotFound if oldHash is absent (concurrent replay).
func (s *SessionStore) RotateToken(_ context.Context, oldHash string, newSess *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.byHash[oldHash]
	if !ok {
		return ports.ErrSessionNotFound
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
