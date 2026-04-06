package app

import (
	"auth-service/internal/app/gateway"
	grpcApp "auth-service/internal/app/grpc"
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
	//timeout time.Duration,
	jwtCfg config.JWTConfig,
	secCfg config.SecurityConfig,
	env string,
) *App {
	uRepo := userRepo.New(db.Pool)
	sRepo := sessionRepo.New(db.Pool)
	jwtManager := jwtlib.New(jwtCfg.Secret, jwtCfg.AccessTTL)

	aRepo := auditRepo.New(db.Pool)
	guard := bruteforce.New(
		redisClient,
		secCfg.BruteForce.MaxAttempts,
		secCfg.BruteForce.Window,
		secCfg.BruteForce.LockoutTTL,
	)

	service := auth.New(uRepo, sRepo, jwtManager, redisClient, aRepo, guard, log, jwtCfg.RefreshTTL)

	globalLimiter := ratelimit.New(redisClient, secCfg.RateLimit.GlobalRPM, time.Minute)
	loginLimiter := ratelimit.New(redisClient, secCfg.RateLimit.LoginRPM, time.Minute)

	grpcApplication := grpcApp.New(service, log, grpcPort,
		grpc.ChainUnaryInterceptor(
			interceptor.Logging(log),
			interceptor.RateLimit(globalLimiter, loginLimiter, log),
		),
	)
	gatewayApplication := gateway.New(log, gatewayPort, grpcPort, env)

	return &App{
		GrpcApp:    grpcApplication,
		GatewayApp: gatewayApplication,
	}
}
