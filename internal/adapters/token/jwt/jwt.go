package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"auth-service/internal/domain/ports"
)

type jwtClaims struct {
	UserID string   `json:"uid"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

func (c *jwtClaims) toPorts() *ports.Claims {
	return &ports.Claims{UserID: c.UserID, Email: c.Email, Roles: c.Roles}
}

// ── HS256 ─────────────────────────────────────────────────────────────────────

type HS256Manager struct {
	secret    []byte
	accessTTL time.Duration
}

func NewHS256Manager(secret string, accessTTL time.Duration) *HS256Manager {
	return &HS256Manager{secret: []byte(secret), accessTTL: accessTTL}
}

// New is a backward-compatible alias for NewHS256Manager.
func New(secret string, accessTTL time.Duration) *HS256Manager {
	return NewHS256Manager(secret, accessTTL)
}

func (m *HS256Manager) GenerateAccessToken(userID, email string, roles []string) (string, error) {
	return signToken(jwt.SigningMethodHS256, m.secret, userID, email, roles, m.accessTTL)
}

func (m *HS256Manager) ValidateAccessToken(tokenStr string) (*ports.Claims, error) {
	return parseToken(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
}

// ── RS256 ─────────────────────────────────────────────────────────────────────

type RS256Manager struct {
	priv      *rsa.PrivateKey
	accessTTL time.Duration
}

func NewRS256Manager(priv *rsa.PrivateKey, accessTTL time.Duration) *RS256Manager {
	return &RS256Manager{priv: priv, accessTTL: accessTTL}
}

func (m *RS256Manager) GenerateAccessToken(userID, email string, roles []string) (string, error) {
	return signToken(jwt.SigningMethodRS256, m.priv, userID, email, roles, m.accessTTL)
}

func (m *RS256Manager) ValidateAccessToken(tokenStr string) (*ports.Claims, error) {
	return parseToken(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &m.priv.PublicKey, nil
	})
}

// ── ES256 ─────────────────────────────────────────────────────────────────────

type ES256Manager struct {
	priv      *ecdsa.PrivateKey
	accessTTL time.Duration
}

func NewES256Manager(priv *ecdsa.PrivateKey, accessTTL time.Duration) *ES256Manager {
	return &ES256Manager{priv: priv, accessTTL: accessTTL}
}

func (m *ES256Manager) GenerateAccessToken(userID, email string, roles []string) (string, error) {
	return signToken(jwt.SigningMethodES256, m.priv, userID, email, roles, m.accessTTL)
}

func (m *ES256Manager) ValidateAccessToken(tokenStr string) (*ports.Claims, error) {
	return parseToken(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &m.priv.PublicKey, nil
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func signToken(method jwt.SigningMethod, key any, userID, email string, roles []string, ttl time.Duration) (string, error) {
	claims := &jwtClaims{
		UserID: userID,
		Email:  email,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			Issuer:    "auth-service",
		},
	}
	t := jwt.NewWithClaims(method, claims)
	signed, err := t.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

func parseToken(tokenStr string, keyFunc jwt.Keyfunc) (*ports.Claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, keyFunc,
		jwt.WithExpirationRequired(),
		jwt.WithIssuer("auth-service"),
	)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	claims, ok := t.Claims.(*jwtClaims)
	if !ok || !t.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims.toPorts(), nil
}

var (
	_ ports.AccessTokenManager = (*HS256Manager)(nil)
	_ ports.AccessTokenManager = (*RS256Manager)(nil)
	_ ports.AccessTokenManager = (*ES256Manager)(nil)
)
