package models

import "time"

type Session struct {
	ID         string
	UserID     string
	UserEmail  string // populated from JOIN when needed
	TokenHash  string
	DeviceID   string
	UserAgent  string
	IPAddress  string
	ExpiresAt  time.Time
	LastUsedAt time.Time
	CreatedAt  time.Time
}
