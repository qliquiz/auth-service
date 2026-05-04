package memory

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/domain/models"
	"auth-service/internal/domain/ports"
)

var _ ports.UserStore = (*UserStore)(nil)

type UserStore struct {
	mu      sync.RWMutex
	byID    map[string]*models.User
	byEmail map[string]*models.User
}

func NewUserStore() *UserStore {
	return &UserStore{
		byID:    make(map[string]*models.User),
		byEmail: make(map[string]*models.User),
	}
}

func (s *UserStore) Create(_ context.Context, email, passwordHash string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byEmail[email]; exists {
		return nil, ports.ErrUserAlreadyExists
	}
	u := &models.User{
		ID:           uuid.NewString(),
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	s.byID[u.ID] = u
	s.byEmail[email] = u
	return u, nil
}

func (s *UserStore) GetByEmail(_ context.Context, email string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byEmail[email]
	if !ok {
		return nil, ports.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *UserStore) GetByID(_ context.Context, id string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok {
		return nil, ports.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}
