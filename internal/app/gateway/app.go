package gateway

import (
	"auth-service/gen/api"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type App struct {
	server     *http.Server
	log        *slog.Logger
	port       int
	grpcTarget string
}

func New(log *slog.Logger, port int, grpcPort int) *App {
	grpcTarget := fmt.Sprintf("localhost:%d", grpcPort)

	return &App{
		log:        log,
		port:       port,
		grpcTarget: grpcTarget,
	}
}

func (a *App) MustRun() {
	if err := a.run(); err != nil {
		panic(err)
	}
}

func (a *App) run() error {
	const op = "gateway.run"
	ctx := context.Background()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	err := api.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, a.grpcTarget, opts)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	a.log.Info("starting gateway", slog.Int("port", a.port))

	a.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", a.port),
		Handler: mux,
	}

	if err = a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop(ctx context.Context) error {
	a.log.Info("stopping gateway")
	return a.server.Shutdown(ctx)
}
