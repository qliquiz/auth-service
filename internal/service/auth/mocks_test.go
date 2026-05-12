package auth_test

import (
	"context"
	"testing"
	"time"

	"auth-service/internal/domain/models"
	"auth-service/internal/domain/ports"

	"github.com/stretchr/testify/mock"
)

type mockUserRepo struct{ mock.Mock }

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
func (m *mockUserRepo) UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error {
	return m.Called(ctx, userID, passwordHash).Error(0)
}

type mockSessionRepo struct{ mock.Mock }

func (m *mockSessionRepo) Create(ctx context.Context, s *models.Session) error {
	return m.Called(ctx, s).Error(0)
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
	return m.Called(ctx, tokenHash).Error(0)
}
func (m *mockSessionRepo) RotateToken(ctx context.Context, oldHash string, newSession *models.Session) error {
	return m.Called(ctx, oldHash, newSession).Error(0)
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
func (m *mockSessionRepo) DeleteAllByUserIDExcept(ctx context.Context, userID, keepTokenHash string) ([]string, error) {
	args := m.Called(ctx, userID, keepTokenHash)
	hashes, _ := args.Get(0).([]string)
	return hashes, args.Error(1)
}

type mockResetStore struct{ mock.Mock }

func (m *mockResetStore) SaveOTP(ctx context.Context, userID, email, otpHash string, ttl time.Duration) error {
	return m.Called(ctx, userID, email, otpHash, ttl).Error(0)
}
func (m *mockResetStore) GetOTP(ctx context.Context, email string) (*ports.OTPRecord, error) {
	args := m.Called(ctx, email)
	r, _ := args.Get(0).(*ports.OTPRecord)
	return r, args.Error(1)
}
func (m *mockResetStore) IncrOTPAttempts(ctx context.Context, email string) (int, error) {
	args := m.Called(ctx, email)
	return args.Int(0), args.Error(1)
}
func (m *mockResetStore) DeleteOTP(ctx context.Context, email string) error {
	return m.Called(ctx, email).Error(0)
}
func (m *mockResetStore) SaveResetToken(ctx context.Context, tokenHash, userID, email string, ttl time.Duration) error {
	return m.Called(ctx, tokenHash, userID, email, ttl).Error(0)
}
func (m *mockResetStore) GetResetToken(ctx context.Context, tokenHash string) (*ports.ResetTokenRecord, error) {
	args := m.Called(ctx, tokenHash)
	r, _ := args.Get(0).(*ports.ResetTokenRecord)
	return r, args.Error(1)
}
func (m *mockResetStore) DeleteResetToken(ctx context.Context, tokenHash string) error {
	return m.Called(ctx, tokenHash).Error(0)
}

// auditSink captures events via a buffered channel. Implements ports.AuditStore.
type auditSink struct {
	events chan *ports.AuditEvent
}

func newAuditSink() *auditSink {
	return &auditSink{events: make(chan *ports.AuditEvent, 10)}
}

func (a *auditSink) Log(_ context.Context, e *ports.AuditEvent) error {
	a.events <- e
	return nil
}

func (a *auditSink) next(t *testing.T) *ports.AuditEvent {
	t.Helper()
	select {
	case e := <-a.events:
		return e
	case <-time.After(500 * time.Millisecond):
		t.Fatal("audit event not received within deadline")
		return nil
	}
}
