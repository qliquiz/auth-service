package main

import (
	"auth-service/internal/app"
	"auth-service/internal/config"
	"auth-service/internal/lib/logger/handlers/slogpretty"
	"auth-service/internal/postgres"
	"auth-service/internal/redis"
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	redis2 "github.com/redis/go-redis/v9"
)

const (
	envLocal = "local"
	envProd  = "prod"
	envDev   = "dev"
)

func main() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)
	log.Info("starting auth-service...")

	initCtx := context.Background()
	redisClient, err := redis.New(initCtx, cfg.Redis)
	if err != nil {
		log.Error("failed to initialize redis client", "error", err)
		os.Exit(1)
	}
	defer func(redisClient *redis2.Client) {
		err = redisClient.Close()
		if err != nil {
			log.Error("failed to close redis client", "error", err)
		}
	}(redisClient)

	db, err := postgres.New(cfg.DB)
	if err != nil {
		log.Error("failed to connect to the database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	log.Info("infrastructure initialized successfully")

	application := app.New(
		db,
		redisClient,
		log,
		cfg.GRPC.Port,
		cfg.Gateway.Port,
		//cfg.GRPC.Timeout,
		cfg.JWT,
		cfg.Security,
		cfg.Env,
	)

	go application.GrpcApp.MustRun()
	go application.GatewayApp.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("shutting down application...", slog.String("signal", sign.String()))

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err = application.GatewayApp.Stop(shutdownCtx); err != nil {
		log.Error("gateway shutdown error", "error", err)
	}
	application.GrpcApp.Stop()

	log.Info("Server Stopped")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = setupPrettySlog()
	case envDev:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envProd:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	return log
}

func setupPrettySlog() *slog.Logger {
	opts := slogpretty.PrettyHandlerOptions{
		SlogOpts: &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	}

	handler := opts.NewPrettyHandler(os.Stdout)

	return slog.New(handler)
}
