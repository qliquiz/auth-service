package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"auth-service/internal/domain/ports"
	"auth-service/internal/lib/token"
)

const (
	otpPrefix        = "pwreset:"
	resetTokenPrefix = "pwreset_token:"
)

var _ ports.PasswordResetStore = (*ResetCache)(nil)

type ResetCache struct {
	client *redis.Client
}

func NewResetCache(client *redis.Client) *ResetCache {
	return &ResetCache{client: client}
}

type otpData struct {
	UserID   string `json:"user_id"`
	OTPHash  string `json:"otp_hash"`
	Attempts int    `json:"attempts"`
}

type resetTokenData struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

func (c *ResetCache) SaveOTP(ctx context.Context, userID, email, otpHash string, ttl time.Duration) error {
	data, _ := json.Marshal(otpData{UserID: userID, OTPHash: otpHash})
	if err := c.client.Set(ctx, otpPrefix+token.Hash(email), data, ttl).Err(); err != nil {
		return fmt.Errorf("save otp: %w", err)
	}
	return nil
}

func (c *ResetCache) GetOTP(ctx context.Context, email string) (*ports.OTPRecord, error) {
	raw, err := c.client.Get(ctx, otpPrefix+token.Hash(email)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ports.ErrResetCodeNotFound
		}
		return nil, fmt.Errorf("get otp: %w", err)
	}
	var d otpData
	if err = json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("unmarshal otp: %w", err)
	}
	return &ports.OTPRecord{UserID: d.UserID, OTPHash: d.OTPHash, Attempts: d.Attempts}, nil
}

func (c *ResetCache) IncrOTPAttempts(ctx context.Context, email string) (int, error) {
	key := otpPrefix + token.Hash(email)

	raw, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, ports.ErrResetCodeNotFound
		}
		return 0, fmt.Errorf("get otp for incr: %w", err)
	}
	var d otpData
	if err = json.Unmarshal(raw, &d); err != nil {
		return 0, fmt.Errorf("unmarshal otp: %w", err)
	}
	d.Attempts++

	ttl, err := c.client.TTL(ctx, key).Result()
	if err != nil || ttl <= 0 {
		return 0, ports.ErrResetCodeNotFound
	}
	updated, _ := json.Marshal(d)
	if err = c.client.Set(ctx, key, updated, ttl).Err(); err != nil {
		return 0, fmt.Errorf("save otp after incr: %w", err)
	}
	return d.Attempts, nil
}

func (c *ResetCache) DeleteOTP(ctx context.Context, email string) error {
	return c.client.Del(ctx, otpPrefix+token.Hash(email)).Err()
}

func (c *ResetCache) SaveResetToken(ctx context.Context, tokenHash, userID, email string, ttl time.Duration) error {
	data, _ := json.Marshal(resetTokenData{UserID: userID, Email: email})
	if err := c.client.Set(ctx, resetTokenPrefix+tokenHash, data, ttl).Err(); err != nil {
		return fmt.Errorf("save reset token: %w", err)
	}
	return nil
}

func (c *ResetCache) GetResetToken(ctx context.Context, tokenHash string) (*ports.ResetTokenRecord, error) {
	raw, err := c.client.Get(ctx, resetTokenPrefix+tokenHash).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ports.ErrResetTokenNotFound
		}
		return nil, fmt.Errorf("get reset token: %w", err)
	}
	var d resetTokenData
	if err = json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("unmarshal reset token: %w", err)
	}
	return &ports.ResetTokenRecord{UserID: d.UserID, Email: d.Email}, nil
}

func (c *ResetCache) DeleteResetToken(ctx context.Context, tokenHash string) error {
	return c.client.Del(ctx, resetTokenPrefix+tokenHash).Err()
}
