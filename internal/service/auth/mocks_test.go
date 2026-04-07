package auth_test

import (
	"context"
	"testing"
	"time"

	"auth-service/internal/domain/models"
	auditRepo "auth-service/internal/repository/audit"

	"github.com/stretchr/testify/mock"
)

// mockUserRepo is a testify mock for the userRepository interface.
type mockUserRepo struct {
	mock.Mock
}

func (m *mockUserRepo) Create(ctx context.Context, email, passwordHash string) (*models.User, error) {
	args := m.Called(ctx, email, passwordHash)
	u, _ := args.Get(0).(*models.User)
	return u, args.Error(1)
}

func (m *mockUserRepo) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	u, _ := args.Get(0).(*models.User)
	return u, args.Error(1)
}

func (m *mockUserRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
	args := m.Called(ctx, id)
	u, _ := args.Get(0).(*models.User)
	return u, args.Error(1)
}

// mockSessionRepo is a testify mock for the sessionRepository interface.
type mockSessionRepo struct {
	mock.Mock
}

func (m *mockSessionRepo) Create(ctx context.Context, s *models.Session) error {
	args := m.Called(ctx, s)
	return args.Error(0)
}

func (m *mockSessionRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	args := m.Called(ctx, tokenHash)
	s, _ := args.Get(0).(*models.Session)
	return s, args.Error(1)
}

func (m *mockSessionRepo) DeleteByID(ctx context.Context, sessionID, userID string) (string, error) {
	args := m.Called(ctx, sessionID, userID)
	return args.String(0), args.Error(1)
}

func (m *mockSessionRepo) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash)
	return args.Error(0)
}

func (m *mockSessionRepo) DeleteAllByUserID(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	hashes, _ := args.Get(0).([]string)
	return hashes, args.Error(1)
}

func (m *mockSessionRepo) ListByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	args := m.Called(ctx, userID)
	s, _ := args.Get(0).([]*models.Session)
	return s, args.Error(1)
}

// mockAuditRepo is a testify mock for the auditRepository interface.
type mockAuditRepo struct {
	mock.Mock
}

func (m *mockAuditRepo) Log(ctx context.Context, e *auditRepo.Event) error {
	args := m.Called(ctx, e)
	return args.Error(0)
}

// auditSink is a lightweight, goroutine-safe audit repo that captures events
// over a buffered channel. Use next() to retrieve the next event or fail fast.
type auditSink struct {
	events chan *auditRepo.Event
}

func newAuditSink() *auditSink {
	return &auditSink{events: make(chan *auditRepo.Event, 10)}
}

func (a *auditSink) Log(_ context.Context, e *auditRepo.Event) error {
	a.events <- e
	return nil
}

// next blocks until an event arrives or the 150 ms deadline expires.
func (a *auditSink) next(t *testing.T) *auditRepo.Event {
	t.Helper()
	select {
	case e := <-a.events:
		return e
	case <-time.After(150 * time.Millisecond):
		t.Fatal("audit event not received within deadline")
		return nil
	}
}
