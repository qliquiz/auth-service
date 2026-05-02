package main

import (
	"auth-service/internal/app"
	"auth-service/internal/config"
	"auth-service/internal/lib/logger/handlers/slogpretty"
	"auth-service/internal/postgres"
	"auth-service/internal/redis"
	"context"
	"fmt"
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
		cfg.GRPC.Timeout,
		cfg.JWT,
		cfg.Security,
		cfg.Env,
	)

	serverErr := make(chan error, 2)
	go func() {
		if err := application.GrpcApp.Run(); err != nil {
			serverErr <- fmt.Errorf("grpc: %w", err)
		}
	}()
	go func() {
		if err := application.GatewayApp.Run(); err != nil {
			serverErr <- fmt.Errorf("gateway: %w", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sign := <-stop:
		log.Info("shutting down application...", slog.String("signal", sign.String()))
	case err := <-serverErr:
		log.Error("server startup failed", slog.String("err", err.Error()))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err = application.GatewayApp.Stop(shutdownCtx); err != nil {
		log.Error("gateway shutdown error", "error", err)
	}
	application.GrpcApp.Stop()

	log.Info("Server Stopped")
}

func setupLogger(env string) *slog.Logger {
	switch env {
	case envLocal:
		return setupPrettySlog()
	case envDev:
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envProd:
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	default:
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error(
			"unknown ENV value, must be one of: local, dev, prod",
			slog.String("env", env),
		)
		os.Exit(1)
		return nil // unreachable
	}
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
