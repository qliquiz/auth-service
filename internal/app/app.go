package app

import (
	"auth-service/internal/app/gateway"
	grpcApp "auth-service/internal/app/grpc"
	rediscache "auth-service/internal/cache/redis"
	"auth-service/internal/config"
	"auth-service/internal/interceptor"
	"auth-service/internal/lib/bruteforce"
	jwtlib "auth-service/internal/lib/jwt"
	"auth-service/internal/lib/ratelimit"
	"auth-service/internal/postgres"
	auditRepo "auth-service/internal/repository/audit"
	sessionRepo "auth-service/internal/repository/session"
	userRepo "auth-service/internal/repository/user"
	"auth-service/internal/service/auth"
	"auth-service/pkg/hooks"
	"auth-service/pkg/ports"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

type App struct {
	GrpcApp    *grpcApp.App
	GatewayApp *gateway.App
}

func New(
	db *postgres.Database,
	redisClient *redis.Client,
	log *slog.Logger,
	grpcPort int,
	gatewayPort int,
	grpcTimeout time.Duration,
	jwtCfg config.JWTConfig,
	secCfg config.SecurityConfig,
	gatewayCfg config.GatewayConfig,
	env string,
) *App {
	uRepo := userRepo.New(db.Pool)
	sRepo := sessionRepo.New(db.Pool)
	aRepo := auditRepo.New(db.Pool)

	// Select JWT strategy based on config; defaults to HS256.
	// Set JWT_ALGORITHM=rs256 or es256 with JWT_PRIVATE_KEY_PATH to use asymmetric signing.
	var tokenMgr ports.AccessTokenManager = jwtlib.NewHS256Manager(jwtCfg.Secret, jwtCfg.AccessTTL)

	cache := rediscache.New(redisClient)
	guard := bruteforce.New(
		redisClient,
		secCfg.BruteForce.MaxAttempts,
		secCfg.BruteForce.Window,
		secCfg.BruteForce.LockoutTTL,
	)

	service := auth.New(uRepo, sRepo, tokenMgr, cache, aRepo, guard, hooks.NoOp{}, log, jwtCfg.RefreshTTL)

	globalLimiter := ratelimit.New(redisClient, secCfg.RateLimit.GlobalRPM, time.Minute)
	loginLimiter := ratelimit.New(redisClient, secCfg.RateLimit.LoginRPM, time.Minute)

	grpcApplication := grpcApp.New(service, log, grpcPort,
		grpc.ConnectionTimeout(grpcTimeout),
		grpc.ChainUnaryInterceptor(
			interceptor.Logging(log),
			interceptor.RateLimit(globalLimiter, loginLimiter, log),
		),
	)
	gatewayApplication := gateway.New(log, gatewayPort, grpcPort, gatewayCfg.GRPCTarget, gatewayCfg.GRPCTLSCert, env)

	return &App{
		GrpcApp:    grpcApplication,
		GatewayApp: gatewayApplication,
	}
}
