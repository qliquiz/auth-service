package app

import (
	"auth-service/internal/app/gateway"
	grpcApp "auth-service/internal/app/grpc"
	"auth-service/internal/postgres"
	"auth-service/internal/repository/user"
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
) *App {
	repo := user.New(db.Pool)
	// В будущем здесь добавим JWT менеджер
	service := auth.New(repo, redisClient, log, timeout)

	grpcApplication := grpcApp.New(service, log, grpcPort)
	gatewayApplication := gateway.New(log, gatewayPort, grpcPort)

	return &App{
		GrpcApp:    grpcApplication,
		GatewayApp: gatewayApplication,
	}
}
