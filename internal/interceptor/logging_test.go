package interceptor_test

import (
	"context"
	"log/slog"
	"testing"

	"auth-service/internal/interceptor"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestLogging_LogsRequestWithoutPanic(t *testing.T) {
	t.Parallel()
	mw := interceptor.Logging(slog.Default())
	_, err := mw(context.Background(), nil, infoFor("Login"), okHandler)
	require.NoError(t, err)
}

// TestLogging_ShortMethodNoSlash covers the fallback branch in shortMethod
// when FullMethod contains no "/" separator.
func TestLogging_ShortMethodNoSlash(t *testing.T) {
	t.Parallel()
	mw := interceptor.Logging(slog.Default())
	info := &grpc.UnaryServerInfo{FullMethod: "BareMethod"}
	_, err := mw(context.Background(), nil, info, okHandler)
	require.NoError(t, err)
}
