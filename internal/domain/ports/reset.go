package ports

import (
	"context"
	"errors"
	"time"
)

var (
	ErrResetCodeNotFound  = errors.New("reset code not found or expired")
	ErrResetTokenNotFound = errors.New("reset token not found or expired")
)

type OTPRecord struct {
	UserID   string
	OTPHash  string
	Attempts int
}

type ResetTokenRecord struct {
	UserID string
	Email  string
}

type PasswordResetStore interface {
	SaveOTP(ctx context.Context, userID, email, otpHash string, ttl time.Duration) error
	GetOTP(ctx context.Context, email string) (*OTPRecord, error)
	IncrOTPAttempts(ctx context.Context, email string) (int, error)
	DeleteOTP(ctx context.Context, email string) error

	SaveResetToken(ctx context.Context, tokenHash, userID, email string, ttl time.Duration) error
	GetResetToken(ctx context.Context, tokenHash string) (*ResetTokenRecord, error)
	DeleteResetToken(ctx context.Context, tokenHash string) error
}
