package grpcapp

import (
	"auth-service/internal/service/auth"
	"fmt"
	"log/slog"
	"net"

	"google.golang.org/grpc"
)

type App struct {
	gRPCServer *grpc.Server
	log        *slog.Logger
	port       int
}

func New(
	authService *auth.AuthService,
	log *slog.Logger,
	port int,
) *App {
	gRPCServer := grpc.NewServer()

	auth.Register(gRPCServer, authService)

	return &App{
		gRPCServer: gRPCServer,
		log:        log,
		port:       port,
	}
}

func (a *App) MustRun() {
	if err := a.run(); err != nil {
		panic(err)
	}
}

func (a *App) run() error {
	const op = "grpcapp.run"
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	a.log.Info("grpc server is running", slog.String("addr", lis.Addr().String()))

	if err = a.gRPCServer.Serve(lis); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop() {
	a.log.Info("stopping gRPC server")
	a.gRPCServer.GracefulStop()
}
