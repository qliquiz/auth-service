// Package hooks provides built-in EventHook implementations.
package hooks

import (
	"context"

	"auth-service/pkg/ports"
)

// NoOp is the default hook that silently discards all events.
// Use it when no custom business logic is needed.
type NoOp struct{}

// Compile-time assertion: NoOp must implement ports.EventHook.
var _ ports.EventHook = NoOp{}

func (NoOp) OnEvent(_ context.Context, _ ports.HookEvent) error { return nil }
