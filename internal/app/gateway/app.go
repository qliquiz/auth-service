package gateway

import (
	"auth-service/docs"
	"auth-service/gen/api"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const scalarHTML = `<!DOCTYPE html>
<html>
  <head>
    <title>Auth Service — API Reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      data-url="/openapi.json"
      src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`

type App struct {
	server      *http.Server
	log         *slog.Logger
	port        int
	grpcTarget  string
	grpcTLSCert string
	env         string
	cancelGW    context.CancelFunc
}

// New creates the gateway App. grpcTarget overrides the default localhost:<grpcPort>
// target — set it when the gRPC server runs in a different host/container.
// grpcTLSCert is the path to the gRPC server's TLS certificate; leave empty for
// local/dev single-host deployments (insecure loopback).
func New(log *slog.Logger, port int, grpcPort int, grpcTarget string, grpcTLSCert string, env string) *App {
	target := grpcTarget
	if target == "" {
		target = fmt.Sprintf("localhost:%d", grpcPort)
	}
	return &App{
		log:         log,
		port:        port,
		grpcTarget:  target,
		grpcTLSCert: grpcTLSCert,
		env:         env,
	}
}

// Run starts the HTTP gateway and blocks until it stops. Returns any startup or
// serve error so the caller can handle it without a panic.
func (a *App) Run() error {
	return a.run()
}

func (a *App) MustRun() {
	if err := a.run(); err != nil {
		panic(err)
	}
}

func (a *App) run() error {
	const op = "gateway.run"
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelGW = cancel

	mux := runtime.NewServeMux()

	var transportCreds grpc.DialOption
	if a.grpcTLSCert != "" {
		tlsCreds, err := credentials.NewClientTLSFromFile(a.grpcTLSCert, "")
		if err != nil {
			return fmt.Errorf("%s: load gRPC TLS cert: %w", op, err)
		}
		transportCreds = grpc.WithTransportCredentials(tlsCreds)
	} else {
		if a.env == "prod" {
			a.log.Warn("gateway→gRPC connection is unencrypted; set GATEWAY_GRPC_TLS_CERT in production")
		}
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	opts := []grpc.DialOption{transportCreds}

	if err := api.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, a.grpcTarget, opts); err != nil {
		cancel()
		return fmt.Errorf("%s: %w", op, err)
	}

	if a.env != "prod" {
		if err := mux.HandlePath("GET", "/openapi.json", func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(docs.OpenAPISpec)
		}); err != nil {
			return fmt.Errorf("%s: register /openapi.json: %w", op, err)
		}

		if err := mux.HandlePath("GET", "/docs", func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, scalarHTML)
		}); err != nil {
			return fmt.Errorf("%s: register /docs: %w", op, err)
		}

		a.log.Info("api docs available",
			slog.String("url", fmt.Sprintf("http://localhost:%d/docs", a.port)))
	}

	a.log.Info("starting gateway", slog.Int("port", a.port))

	a.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", a.port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop(ctx context.Context) error {
	a.log.Info("stopping gateway")
	if a.cancelGW != nil {
		a.cancelGW()
	}
	return a.server.Shutdown(ctx)
}
