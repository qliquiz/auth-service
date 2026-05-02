package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"auth-service/gen/api"
	"auth-service/internal/domain/models"
	"auth-service/internal/lib/bruteforce"
	"auth-service/internal/lib/password"
	"auth-service/internal/lib/token"
	"auth-service/internal/lib/validate"
	sessionRepo "auth-service/internal/repository/session"
	userRepo "auth-service/internal/repository/user"
	"auth-service/pkg/ports"
)

// AuthService implements api.AuthServiceServer. All dependencies are injected
// via pkg/ports interfaces so the underlying backends are swappable.
type AuthService struct {
	api.UnimplementedAuthServiceServer
	userStore    ports.UserStore
	sessionStore ports.SessionStore
	auditStore   ports.AuditStore // nil = audit disabled
	tokenMgr     ports.AccessTokenManager
	cache        ports.SessionCache
	hook         ports.EventHook   // nil = no custom hook
	bruteGuard   *bruteforce.Guard // nil = brute-force protection disabled
	log          *slog.Logger
	refreshTTL   time.Duration
}

func New(
	userStore ports.UserStore,
	sessionStore ports.SessionStore,
	tokenMgr ports.AccessTokenManager,
	cache ports.SessionCache,
	auditStore ports.AuditStore,
	bruteGuard *bruteforce.Guard,
	hook ports.EventHook,
	log *slog.Logger,
	refreshTTL time.Duration,
) *AuthService {
	return &AuthService{
		userStore:    userStore,
		sessionStore: sessionStore,
		auditStore:   auditStore,
		tokenMgr:     tokenMgr,
		cache:        cache,
		hook:         hook,
		bruteGuard:   bruteGuard,
		log:          log,
		refreshTTL:   refreshTTL,
	}
}

func Register(gRPC *grpc.Server, authService *AuthService) {
	api.RegisterAuthServiceServer(gRPC, authService)
}

// ── Register ──────────────────────────────────────────────────────────────────

func (s *AuthService) Register(ctx context.Context, req *api.RegisterRequest) (*api.RegisterResponse, error) {
	const op = "auth.Register"

	if err := validate.Email(req.Email); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := validate.Password(req.Password); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Log only after validation — avoids writing untrusted/malformed input to logs.
	log := s.log.With(slog.String("op", op), slog.String("email", req.Email))

	hash, err := password.Hash(req.Password)
	if err != nil {
		log.Error("hash password", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	user, err := s.userStore.Create(ctx, req.Email, hash)
	if err != nil {
		if errors.Is(err, userRepo.ErrAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "email already registered")
		}
		log.Error("create user", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	ipAddr, userAgent := extractClientInfo(ctx)
	s.logAudit(strPtr(user.ID), ports.AuditEventRegister, ipAddr, userAgent,
		map[string]string{"email": user.Email})
	s.fireHook(user.ID, user.Email, ports.AuditEventRegister, ipAddr, userAgent,
		map[string]string{"email": user.Email})

	log.Info("user registered", slog.String("user_id", user.ID))
	return &api.RegisterResponse{UserId: user.ID}, nil
}

// ── Login ─────────────────────────────────────────────────────────────────────

func (s *AuthService) Login(ctx context.Context, req *api.LoginRequest) (*api.LoginResponse, error) {
	const op = "auth.Login"

	if err := validate.Email(req.Email); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Log only after validation — avoids writing untrusted/malformed input to logs.
	log := s.log.With(slog.String("op", op), slog.String("email", req.Email))

	ipAddr, userAgent := extractClientInfo(ctx)

	// Brute-force: check lockout before any DB lookup.
	if s.bruteGuard != nil {
		locked, err := s.bruteGuard.IsLocked(ctx, req.Email)
		if err != nil {
			log.Error("check brute force", slog.String("err", err.Error()))
		} else if locked {
			s.logAudit(nil, ports.AuditEventLoginBlocked, ipAddr, userAgent,
				map[string]string{"email": req.Email})
			s.fireHook("", req.Email, ports.AuditEventLoginBlocked, ipAddr, userAgent,
				map[string]string{"email": req.Email})
			return nil, status.Error(codes.ResourceExhausted,
				"account temporarily locked due to too many failed attempts, try again later")
		}
	}

	user, err := s.userStore.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, userRepo.ErrNotFound) {
			s.logAudit(nil, ports.AuditEventLoginFailure, ipAddr, userAgent,
				map[string]string{"email": req.Email})
			s.fireHook("", req.Email, ports.AuditEventLoginFailure, ipAddr, userAgent,
				map[string]string{"email": req.Email})
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
		if s.bruteGuard != nil {
			if wasLocked, bErr := s.bruteGuard.RecordFailure(ctx, req.Email); bErr != nil {
				log.Error("record brute force failure", slog.String("err", bErr.Error()))
			} else if wasLocked {
				s.logAudit(strPtr(user.ID), ports.AuditEventLoginBlocked, ipAddr, userAgent,
					map[string]string{"email": req.Email})
				s.fireHook(user.ID, user.Email, ports.AuditEventLoginBlocked, ipAddr, userAgent,
					map[string]string{"email": req.Email})
				return nil, status.Error(codes.ResourceExhausted,
					"account temporarily locked due to too many failed attempts, try again later")
			}
		}
		s.logAudit(strPtr(user.ID), ports.AuditEventLoginFailure, ipAddr, userAgent,
			map[string]string{"email": req.Email})
		s.fireHook(user.ID, user.Email, ports.AuditEventLoginFailure, ipAddr, userAgent,
			map[string]string{"email": req.Email})
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Reset brute-force counter on successful authentication.
	if s.bruteGuard != nil {
		s.bruteGuard.Reset(ctx, req.Email)
	}

	accessToken, err := s.tokenMgr.GenerateAccessToken(user.ID, user.Email, []string{"user"})
	if err != nil {
		log.Error("generate access token", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	plainRefresh, hashedRefresh, err := token.Generate()
	if err != nil {
		log.Error("generate refresh token", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

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

	if err = s.sessionStore.Create(ctx, sess); err != nil {
		log.Error("create session", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	s.cacheSession(ctx, hashedRefresh, &ports.CachedSession{
		SessionID: sess.ID,
		UserID:    user.ID,
		UserEmail: user.Email,
		DeviceID:  deviceID,
		ExpiresAt: sess.ExpiresAt,
	})

	s.logAudit(strPtr(user.ID), ports.AuditEventLoginSuccess, ipAddr, userAgent,
		map[string]string{"email": user.Email, "device_id": deviceID, "session_id": sess.ID})
	s.fireHook(user.ID, user.Email, ports.AuditEventLoginSuccess, ipAddr, userAgent,
		map[string]string{"email": user.Email, "device_id": deviceID, "session_id": sess.ID})

	log.Info("user logged in", slog.String("user_id", user.ID), slog.String("session_id", sess.ID))
	return &api.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: plainRefresh,
	}, nil
}

// ── ValidateToken ─────────────────────────────────────────────────────────────

func (s *AuthService) ValidateToken(_ context.Context, req *api.ValidateTokenRequest) (*api.ValidateTokenResponse, error) {
	claims, err := s.tokenMgr.ValidateAccessToken(req.Token)
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
		dbSess, dbErr := s.sessionStore.GetByTokenHash(ctx, tokenHash)
		if dbErr != nil {
			if errors.Is(dbErr, sessionRepo.ErrNotFound) {
				return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
			}
			log.Error("get session from db", slog.String("err", dbErr.Error()))
			return nil, status.Error(codes.Internal, "internal error")
		}
		cached = &ports.CachedSession{
			SessionID: dbSess.ID,
			UserID:    dbSess.UserID,
			UserEmail: dbSess.UserEmail,
			DeviceID:  dbSess.DeviceID,
			ExpiresAt: dbSess.ExpiresAt,
		}
	}

	if time.Now().After(cached.ExpiresAt) {
		if delErr := s.sessionStore.DeleteByTokenHash(ctx, tokenHash); delErr != nil && !errors.Is(delErr, sessionRepo.ErrNotFound) {
			log.Error("delete expired session", slog.String("err", delErr.Error()))
		}
		s.deleteSessionFromCache(ctx, tokenHash)
		return nil, status.Error(codes.Unauthenticated, "refresh token expired")
	}

	// Rotate tokens.
	newAccessToken, err := s.tokenMgr.GenerateAccessToken(cached.UserID, cached.UserEmail, []string{"user"})
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

	// Atomically invalidate the old session and create the new one.
	// RotateToken uses a DB transaction and verifies the old token was actually
	// deleted (RowsAffected == 1), preventing concurrent refresh-token replay.
	if err = s.sessionStore.RotateToken(ctx, tokenHash, newSess); err != nil {
		if errors.Is(err, sessionRepo.ErrNotFound) {
			// Another concurrent request already consumed this token.
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		}
		log.Error("rotate session", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}
	s.deleteSessionFromCache(ctx, tokenHash)
	s.cacheSession(ctx, newHash, &ports.CachedSession{
		SessionID: newSess.ID,
		UserID:    cached.UserID,
		UserEmail: cached.UserEmail,
		DeviceID:  deviceID,
		ExpiresAt: newSess.ExpiresAt,
	})

	s.logAudit(strPtr(cached.UserID), ports.AuditEventTokenRefresh, ipAddr, userAgent,
		map[string]string{"session_id": newSess.ID})
	s.fireHook(cached.UserID, cached.UserEmail, ports.AuditEventTokenRefresh, ipAddr, userAgent,
		map[string]string{"session_id": newSess.ID})

	return &api.RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newPlain,
	}, nil
}

// ── Logout ────────────────────────────────────────────────────────────────────

func (s *AuthService) Logout(ctx context.Context, req *api.LogoutRequest) (*api.LogoutResponse, error) {
	const op = "auth.Logout"

	tokenHash := token.Hash(req.RefreshToken)

	// Resolve the user ID for audit purposes before deleting. The cache is the
	// cheapest source; on a miss we leave userID nil rather than doing an extra
	// DB round-trip on the hot path.
	var userID *string
	var userEmail string
	if cached, err := s.getCachedSession(ctx, tokenHash); err == nil {
		userID = strPtr(cached.UserID)
		userEmail = cached.UserEmail
	}

	if err := s.sessionStore.DeleteByTokenHash(ctx, tokenHash); err != nil {
		if errors.Is(err, sessionRepo.ErrNotFound) {
			// Token already expired or revoked — idempotent success.
			return &api.LogoutResponse{}, nil
		}
		s.log.With(slog.String("op", op)).Error("delete session", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}
	s.deleteSessionFromCache(ctx, tokenHash)

	ipAddr, userAgent := extractClientInfo(ctx)
	s.logAudit(userID, ports.AuditEventLogout, ipAddr, userAgent, nil)
	uid := ""
	if userID != nil {
		uid = *userID
	}
	s.fireHook(uid, userEmail, ports.AuditEventLogout, ipAddr, userAgent, nil)

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

	hashes, err := s.sessionStore.DeleteAllByUserID(ctx, userID)
	if err != nil {
		log.Error("delete all sessions", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}

	for _, h := range hashes {
		s.deleteSessionFromCache(ctx, h)
	}

	ipAddr, userAgent := extractClientInfo(ctx)
	s.logAudit(strPtr(userID), ports.AuditEventLogoutAll, ipAddr, userAgent,
		map[string]string{"sessions_revoked": fmt.Sprintf("%d", len(hashes))})
	// email is empty here — JWT claims carry only the userID in these operations.
	s.fireHook(userID, "", ports.AuditEventLogoutAll, ipAddr, userAgent,
		map[string]string{"sessions_revoked": fmt.Sprintf("%d", len(hashes))})

	log.Info("all sessions revoked", slog.String("user_id", userID), slog.Int("count", len(hashes)))
	return &api.LogoutAllResponse{SessionsRevoked: int32(len(hashes))}, nil
}

// ── ListSessions ──────────────────────────────────────────────────────────────

func (s *AuthService) ListSessions(ctx context.Context, _ *api.ListSessionsRequest) (*api.ListSessionsResponse, error) {
	const op = "auth.ListSessions"
	log := s.log.With(slog.String("op", op))

	userID, err := s.extractUserIDFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	sessions, err := s.sessionStore.ListByUserID(ctx, userID)
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

	tokenHash, err := s.sessionStore.DeleteByID(ctx, req.SessionId, userID)
	if err != nil {
		if errors.Is(err, sessionRepo.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "session not found")
		}
		log.Error("delete session", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, "internal error")
	}
	s.deleteSessionFromCache(ctx, tokenHash)

	ipAddr, userAgent := extractClientInfo(ctx)
	s.logAudit(strPtr(userID), ports.AuditEventSessionRevoke, ipAddr, userAgent,
		map[string]string{"session_id": req.SessionId})
	// email is empty here — JWT claims carry only the userID in these operations.
	s.fireHook(userID, "", ports.AuditEventSessionRevoke, ipAddr, userAgent,
		map[string]string{"session_id": req.SessionId})

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

	tokenStr, ok := strings.CutPrefix(authHeaders[0], "Bearer ")
	if !ok {
		return "", status.Error(codes.Unauthenticated, "invalid authorization header format")
	}
	claims, err := s.tokenMgr.ValidateAccessToken(tokenStr)
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
			// Use the rightmost IP — appended by gRPC-Gateway (our trusted proxy).
			// The leftmost IPs are client-supplied and must not be trusted.
			parts := strings.Split(xff[0], ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if ip := strings.TrimSpace(parts[i]); ip != "" {
					ipAddress = ip
					break
				}
			}
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

// cacheSession stores a session via the SessionCache with TTL until expiry.
func (s *AuthService) cacheSession(ctx context.Context, tokenHash string, sess *ports.CachedSession) {
	ttl := time.Until(sess.ExpiresAt)
	if ttl <= 0 {
		return
	}
	if err := s.cache.Set(ctx, tokenHash, sess, ttl); err != nil {
		s.log.Error("set session cache", slog.String("err", err.Error()))
	}
}

// getCachedSession retrieves a session from the cache.
func (s *AuthService) getCachedSession(ctx context.Context, tokenHash string) (*ports.CachedSession, error) {
	return s.cache.Get(ctx, tokenHash)
}

// deleteSessionFromCache removes a session from the cache.
func (s *AuthService) deleteSessionFromCache(ctx context.Context, tokenHash string) {
	if err := s.cache.Delete(ctx, tokenHash); err != nil {
		s.log.Error("delete session cache", slog.String("err", err.Error()))
	}
}

// logAudit writes a security event asynchronously so it doesn't block the request path.
func (s *AuthService) logAudit(userID *string, eventType ports.AuditEventType, ip, ua string, meta map[string]string) {
	if s.auditStore == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.auditStore.Log(ctx, &ports.AuditEvent{
			UserID:    userID,
			EventType: eventType,
			IPAddress: ip,
			UserAgent: ua,
			Metadata:  meta,
		}); err != nil {
			s.log.Error("audit log", slog.String("event", string(eventType)), slog.String("err", err.Error()))
		}
	}()
}

// fireHook dispatches an auth lifecycle event to the configured hook asynchronously.
func (s *AuthService) fireHook(userID, email string, eventType ports.AuditEventType, ip, ua string, meta map[string]string) {
	if s.hook == nil {
		return
	}
	go func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.hook.OnEvent(ctx2, ports.HookEvent{
			Type:      eventType,
			UserID:    userID,
			UserEmail: email,
			IPAddress: ip,
			UserAgent: ua,
			Metadata:  meta,
		}); err != nil {
			s.log.Error("hook error", slog.String("event", string(eventType)), slog.String("err", err.Error()))
		}
	}()
}

// strPtr returns a pointer to a string value.
func strPtr(s string) *string { return &s }
