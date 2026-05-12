package interceptor

import (
	"auth-service/internal/lib/ratelimit"
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// sensitiveMethods receive a stricter per-IP rate limit because they are the
// primary attack surface for credential stuffing and enumeration attacks.
var sensitiveMethods = map[string]bool{
	"Login":                true,
	"Register":             true,
	"ChangePassword":       true,
	"RequestPasswordReset": true,
	"VerifyResetCode":      true,
	"ResetPassword":        true,
}

// RateLimit returns a gRPC unary server interceptor that enforces two rate limits:
//   - globalLimiter: applied to every request
//   - loginLimiter:  applied only to Login and Register (stricter)
//
// On Redis failure the limiter fails open so a Redis outage doesn't take down auth.
func RateLimit(globalLimiter, loginLimiter *ratelimit.Limiter, log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		ip := extractIP(ctx)
		method := shortMethod(info.FullMethod)

		// Global rate limit.
		if allowed, err := globalLimiter.Allow(ctx, ip); err != nil {
			log.Warn("rate limit check failed, failing open", slog.String("err", err.Error()))
		} else if !allowed {
			return nil, status.Errorf(codes.ResourceExhausted,
				"too many requests from your IP, try again in %v", globalLimiter.Window())
		}

		// Stricter limit for credential endpoints.
		if sensitiveMethods[method] {
			if allowed, err := loginLimiter.Allow(ctx, "auth:"+ip); err != nil {
				log.Warn("auth rate limit check failed, failing open", slog.String("err", err.Error()))
			} else if !allowed {
				return nil, status.Errorf(codes.ResourceExhausted,
					"too many login attempts from your IP, try again in %v", loginLimiter.Window())
			}
		}

		return handler(ctx, req)
	}
}

// extractIP reads the client IP from X-Forwarded-For metadata (set by gRPC-Gateway
// when the request comes via HTTP) or falls back to the gRPC peer address.
//
// We take the rightmost (last) IP in the XFF list because gRPC-Gateway appends
// the actual client address it received, so the last entry is the one added by
// our own trusted proxy and cannot be forged by the client. The leftmost entries
// are client-supplied and must not be trusted for rate-limiting decisions.
// This assumption holds when the service sits behind exactly one trusted proxy
// (i.e., gRPC-Gateway). If there are additional proxies in front, adjust
// accordingly by trusting the last N entries from the right.
func extractIP(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
			parts := strings.Split(xff[0], ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if ip := strings.TrimSpace(parts[i]); ip != "" {
					return ip
				}
			}
		}
	}
	return peerIP(ctx)
}
