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
	data, err := json.Marshal(otpData{UserID: userID, OTPHash: otpHash})
	if err != nil {
		return fmt.Errorf("marshal otp: %w", err)
	}
	if err = c.client.Set(ctx, otpPrefix+token.Hash(email), data, ttl).Err(); err != nil {
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

// incrOTPScript atomically increments the attempts counter inside the stored JSON blob.
// Returns the new attempts count, or -1 if the key is missing or already expired.
var incrOTPScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if raw == false then return -1 end
local d = cjson.decode(raw)
d.attempts = (d.attempts or 0) + 1
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return -1 end
redis.call('SET', KEYS[1], cjson.encode(d), 'PX', ttl)
return d.attempts
`)

func (c *ResetCache) IncrOTPAttempts(ctx context.Context, email string) (int, error) {
	key := otpPrefix + token.Hash(email)
	n, err := incrOTPScript.Run(ctx, c.client, []string{key}).Int()
	if err != nil {
		return 0, fmt.Errorf("incr otp attempts: %w", err)
	}
	if n == -1 {
		return 0, ports.ErrResetCodeNotFound
	}
	return n, nil
}

func (c *ResetCache) DeleteOTP(ctx context.Context, email string) error {
	return c.client.Del(ctx, otpPrefix+token.Hash(email)).Err()
}

func (c *ResetCache) SaveResetToken(ctx context.Context, tokenHash, userID, email string, ttl time.Duration) error {
	data, err := json.Marshal(resetTokenData{UserID: userID, Email: email})
	if err != nil {
		return fmt.Errorf("marshal reset token: %w", err)
	}
	if err = c.client.Set(ctx, resetTokenPrefix+tokenHash, data, ttl).Err(); err != nil {
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
