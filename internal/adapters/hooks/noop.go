package hooks

import (
	"context"

	"auth-service/internal/domain/ports"
)

type NoOp struct{}

var _ ports.EventHook = NoOp{}

func (NoOp) OnEvent(_ context.Context, _ ports.HookEvent) error { return nil }
