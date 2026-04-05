package app

import (
	"auth-service/internal/app/gateway"
	grpcApp "auth-service/internal/app/grpc"
	"auth-service/internal/config"
	jwtlib "auth-service/internal/lib/jwt"
	"auth-service/internal/postgres"
	sessionRepo "auth-service/internal/repository/session"
	userRepo "auth-service/internal/repository/user"
	"auth-service/internal/service/auth"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
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
	timeout time.Duration,
	jwtCfg config.JWTConfig,
	env string,
) *App {
	uRepo := userRepo.New(db.Pool)
	sRepo := sessionRepo.New(db.Pool)
	jwtManager := jwtlib.New(jwtCfg.Secret, jwtCfg.AccessTTL)

	service := auth.New(uRepo, sRepo, jwtManager, redisClient, log, jwtCfg.RefreshTTL)

	grpcApplication := grpcApp.New(service, log, grpcPort)
	gatewayApplication := gateway.New(log, gatewayPort, grpcPort, env)

	return &App{
		GrpcApp:    grpcApplication,
		GatewayApp: gatewayApplication,
	}
}
