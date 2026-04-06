// Package interceptor contains gRPC server interceptors.
package interceptor

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Logging returns a gRPC unary server interceptor that logs every request
// with its method name, peer IP, duration, and final status code.
func Logging(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		log.Info("grpc",
			slog.String("method", shortMethod(info.FullMethod)),
			slog.String("ip", peerIP(ctx)),
			slog.Duration("dur", time.Since(start).Round(time.Millisecond)),
			slog.String("status", code.String()),
		)

		return resp, err
	}
}

// shortMethod extracts the RPC name from a full gRPC method string.
// e.g. "/api.AuthService/Login" → "Login"
func shortMethod(full string) string {
	if idx := strings.LastIndex(full, "/"); idx >= 0 {
		return full[idx+1:]
	}
	return full
}

// peerIP extracts the remote IP address from the gRPC peer context.
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	addr := p.Addr.String()
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[:idx]
	}
	return addr
}
