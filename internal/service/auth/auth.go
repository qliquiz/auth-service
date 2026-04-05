package auth

import (
	"auth-service/gen/api"
	"auth-service/internal/domain/models"
	jwtlib "auth-service/internal/lib/jwt"
	"auth-service/internal/lib/password"
	"auth-service/internal/lib/token"
	sessionRepo "auth-service/internal/repository/session"
	userRepo "auth-service/internal/repository/user"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const redisSessionPrefix = "refresh:"

// redisSession is the value stored in Redis for a refresh token.
type redisSession struct {
	SessionID string    `json:"sid"`
	UserID    string    `json:"uid"`
	UserEmail string    `json:"email"`
	DeviceID  string    `json:"did"`
	ExpiresAt time.Time `json:"exp"`
}

type AuthService struct {
	api.UnimplementedAuthServiceServer
	userRepo    *userRepo.UserRepository
	sessionRepo *sessionRepo.SessionRepository
	jwtManager  *jwtlib.Manager
	redis       *redis.Client
	log         *slog.Logger
	refreshTTL  time.Duration
}

func New(
	userRepository *userRepo.UserRepository,
	sessionRepository *sessionRepo.SessionRepository,
	jwtManager *jwtlib.Manager,
	redisClient *redis.Client,
	log *slog.Logger,
	refreshTTL time.Duration,
) *AuthService {
	return &AuthService{
		userRepo:    userRepository,
		sessionRepo: sessionRepository,
		jwtManager:  jwtManager,
		redis:       redisClient,
		log:         log,
		refreshTTL:  refreshTTL,
	}
}

func Register(gRPC *grpc.Server, authService *AuthService) {
	api.RegisterAuthServiceServer(gRPC, authService)
}

// ── Register ──────────────────────────────────────────────────────────────────

func (s *AuthService) Register(ctx context.Context, req *api.RegisterRequest) (*api.RegisterResponse, error) {
	const op = "auth.Register"
	log := s.log.With(slog.String("op", op), slog.String("email", req.Email))

	if err := validateEmail(req.Email); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := validatePassword(req.Password); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	hash, err := password.Hash(req.Password)
	if err != nil {
		log.Error("hash password", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	user, err := s.userRepo.Create(ctx, req.Email, hash)
	if err != nil {
		if errors.Is(err, userRepo.ErrAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "email already registered")
		}
		log.Error("create user", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	log.Info("user registered", slog.String("user_id", user.ID))
	return &api.RegisterResponse{UserId: user.ID}, nil
}

// ── Login ─────────────────────────────────────────────────────────────────────

func (s *AuthService) Login(ctx context.Context, req *api.LoginRequest) (*api.LoginResponse, error) {
	const op = "auth.Login"
	log := s.log.With(slog.String("op", op), slog.String("email", req.Email))

	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, userRepo.ErrNotFound) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		log.Error("get user", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	match, err := password.Verify(req.Password, user.PasswordHash)
	if err != nil {
		log.Error("verify password", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}
	if !match {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, []string{"user"})
	if err != nil {
		log.Error("generate access token", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	plainRefresh, hashedRefresh, err := token.Generate()
	if err != nil {
		log.Error("generate refresh token", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	ipAddr, userAgent := extractClientInfo(ctx)
	deviceID := req.DeviceId
	if deviceID == "" {
		deviceID = userAgent
	}

	sess := &models.Session{
		UserID:    user.ID,
		TokenHash: hashedRefresh,
		DeviceID:  deviceID,
		UserAgent: userAgent,
		IPAddress: ipAddr,
		ExpiresAt: time.Now().Add(s.refreshTTL),
	}

	if err = s.sessionRepo.Create(ctx, sess); err != nil {
		log.Error("create session", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	s.cacheSession(ctx, hashedRefresh, &redisSession{
		SessionID: sess.ID,
		UserID:    user.ID,
		UserEmail: user.Email,
		DeviceID:  deviceID,
		ExpiresAt: sess.ExpiresAt,
	})

	log.Info("user logged in", slog.String("user_id", user.ID), slog.String("session_id", sess.ID))
	return &api.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: plainRefresh,
	}, nil
}

// ── ValidateToken ─────────────────────────────────────────────────────────────

func (s *AuthService) ValidateToken(_ context.Context, req *api.ValidateTokenRequest) (*api.ValidateTokenResponse, error) {
	claims, err := s.jwtManager.ValidateAccessToken(req.Token)
	if err != nil {
		return &api.ValidateTokenResponse{Valid: false}, nil
	}

	return &api.ValidateTokenResponse{
		Valid:  true,
		UserId: claims.UserID,
		Roles:  claims.Roles,
	}, nil
}

// ── RefreshToken ──────────────────────────────────────────────────────────────

func (s *AuthService) RefreshToken(ctx context.Context, req *api.RefreshTokenRequest) (*api.RefreshTokenResponse, error) {
	const op = "auth.RefreshToken"
	log := s.log.With(slog.String("op", op))

	tokenHash := token.Hash(req.RefreshToken)

	// Fast path: try Redis cache first.
	cached, err := s.getCachedSession(ctx, tokenHash)
	if err != nil {
		// Cache miss — fall back to DB (also handles Redis unavailability).
		dbSess, dbErr := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
		if dbErr != nil {
			if errors.Is(dbErr, sessionRepo.ErrNotFound) {
				return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
			}
			log.Error("get session from db", slog.String("err", dbErr.Error()))
			return nil, status.Error(codes.Internal, "internal error")
		}
		cached = &redisSession{
			SessionID: dbSess.ID,
			UserID:    dbSess.UserID,
			UserEmail: dbSess.UserEmail,
			DeviceID:  dbSess.DeviceID,
			ExpiresAt: dbSess.ExpiresAt,
		}
	}

	if time.Now().After(cached.ExpiresAt) {
		_ = s.sessionRepo.DeleteByTokenHash(ctx, tokenHash)
		s.deleteSessionFromCache(ctx, tokenHash)
		return nil, status.Error(codes.Unauthenticated, "refresh token expired")
	}

	// Rotate tokens.
	newAccessToken, err := s.jwtManager.GenerateAccessToken(cached.UserID, cached.UserEmail, []string{"user"})
	if err != nil {
		log.Error("generate access token", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	newPlain, newHash, err := token.Generate()
	if err != nil {
		log.Error("generate refresh token", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	ipAddr, userAgent := extractClientInfo(ctx)
	deviceID := req.DeviceId
	if deviceID == "" {
		deviceID = cached.DeviceID
	}

	newSess := &models.Session{
		UserID:    cached.UserID,
		TokenHash: newHash,
		DeviceID:  deviceID,
		UserAgent: userAgent,
		IPAddress: ipAddr,
		ExpiresAt: time.Now().Add(s.refreshTTL),
	}

	// Invalidate old, create new.
	if err = s.sessionRepo.DeleteByTokenHash(ctx, tokenHash); err != nil {
		log.Error("delete old session", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}
	s.deleteSessionFromCache(ctx, tokenHash)

	if err = s.sessionRepo.Create(ctx, newSess); err != nil {
		log.Error("create new session", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}
	s.cacheSession(ctx, newHash, &redisSession{
		SessionID: newSess.ID,
		UserID:    cached.UserID,
		UserEmail: cached.UserEmail,
		DeviceID:  deviceID,
		ExpiresAt: newSess.ExpiresAt,
	})

	return &api.RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newPlain,
	}, nil
}

// ── Logout ────────────────────────────────────────────────────────────────────

func (s *AuthService) Logout(ctx context.Context, req *api.LogoutRequest) (*api.LogoutResponse, error) {
	const op = "auth.Logout"

	tokenHash := token.Hash(req.RefreshToken)

	if err := s.sessionRepo.DeleteByTokenHash(ctx, tokenHash); err != nil {
		s.log.With(slog.String("op", op)).Error("delete session", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}
	s.deleteSessionFromCache(ctx, tokenHash)

	return &api.LogoutResponse{}, nil
}

// ── LogoutAll ─────────────────────────────────────────────────────────────────

func (s *AuthService) LogoutAll(ctx context.Context, _ *api.LogoutAllRequest) (*api.LogoutAllResponse, error) {
	const op = "auth.LogoutAll"
	log := s.log.With(slog.String("op", op))

	userID, err := s.extractUserIDFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	count, err := s.sessionRepo.DeleteAllByUserID(ctx, userID)
	if err != nil {
		log.Error("delete all sessions", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Redis cache entries expire on their own TTL; no bulk delete needed.
	log.Info("all sessions revoked", slog.String("user_id", userID), slog.Int64("count", count))
	return &api.LogoutAllResponse{SessionsRevoked: int32(count)}, nil
}

// ── ListSessions ──────────────────────────────────────────────────────────────

func (s *AuthService) ListSessions(ctx context.Context, _ *api.ListSessionsRequest) (*api.ListSessionsResponse, error) {
	const op = "auth.ListSessions"
	log := s.log.With(slog.String("op", op))

	userID, err := s.extractUserIDFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	sessions, err := s.sessionRepo.ListByUserID(ctx, userID)
	if err != nil {
		log.Error("list sessions", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	infos := make([]*api.SessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		infos = append(infos, &api.SessionInfo{
			SessionId:  sess.ID,
			DeviceId:   sess.DeviceID,
			UserAgent:  sess.UserAgent,
			IpAddress:  sess.IPAddress,
			CreatedAt:  sess.CreatedAt.Unix(),
			LastUsedAt: sess.LastUsedAt.Unix(),
		})
	}

	return &api.ListSessionsResponse{Sessions: infos}, nil
}

// ── RevokeSession ─────────────────────────────────────────────────────────────

func (s *AuthService) RevokeSession(ctx context.Context, req *api.RevokeSessionRequest) (*api.RevokeSessionResponse, error) {
	const op = "auth.RevokeSession"
	log := s.log.With(slog.String("op", op))

	userID, err := s.extractUserIDFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	if err = s.sessionRepo.DeleteByID(ctx, req.SessionId, userID); err != nil {
		if errors.Is(err, sessionRepo.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "session not found")
		}
		log.Error("delete session", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	// We don't have the token_hash here, so the Redis key will expire on its own TTL.
	return &api.RevokeSessionResponse{}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// extractUserIDFromCtx parses the Bearer token from the gRPC metadata Authorization header.
func (s *AuthService) extractUserIDFromCtx(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	tokenStr := strings.TrimPrefix(authHeaders[0], "Bearer ")
	claims, err := s.jwtManager.ValidateAccessToken(tokenStr)
	if err != nil {
		return "", status.Error(codes.Unauthenticated, "invalid access token")
	}

	return claims.UserID, nil
}

// extractClientInfo reads IP and User-Agent from gRPC metadata (set by grpc-gateway)
// or falls back to the peer address for direct gRPC connections.
func extractClientInfo(ctx context.Context) (ipAddress, userAgent string) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
			ipAddress = strings.TrimSpace(strings.Split(xff[0], ",")[0])
		}
		if ua := md.Get("user-agent"); len(ua) > 0 {
			userAgent = ua[0]
		}
		if ipAddress == "" {
			if xri := md.Get("x-real-ip"); len(xri) > 0 {
				ipAddress = xri[0]
			}
		}
	}

	if ipAddress == "" {
		if p, ok := peer.FromContext(ctx); ok {
			if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
				ipAddress = host
			}
		}
	}

	return ipAddress, userAgent
}

// cacheSession stores a session in Redis with TTL until expiry.
func (s *AuthService) cacheSession(ctx context.Context, tokenHash string, sess *redisSession) {
	data, err := json.Marshal(sess)
	if err != nil {
		s.log.Error("marshal redis session", slog.String("err", err.Error()))
		return
	}
	ttl := time.Until(sess.ExpiresAt)
	if ttl <= 0 {
		return
	}
	key := redisSessionPrefix + tokenHash
	if err = s.redis.Set(ctx, key, data, ttl).Err(); err != nil {
		s.log.Error("set redis session", slog.String("err", err.Error()))
	}
}

// getCachedSession retrieves a session from Redis.
func (s *AuthService) getCachedSession(ctx context.Context, tokenHash string) (*redisSession, error) {
	key := redisSessionPrefix + tokenHash
	data, err := s.redis.Get(ctx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("redis get: %w", err)
	}
	var sess redisSession
	if err = json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &sess, nil
}

// deleteSessionFromCache removes a session from Redis.
func (s *AuthService) deleteSessionFromCache(ctx context.Context, tokenHash string) {
	s.redis.Del(ctx, redisSessionPrefix+tokenHash)
}

// ── Validation ────────────────────────────────────────────────────────────────

func validateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

func validatePassword(pwd string) error {
	if len(pwd) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	return nil
}
