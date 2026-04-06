//go:build integration || e2e

package testutil

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Suite holds a single PostgreSQL container shared across all tests in a package.
// Use it via TestMain to avoid spinning up a new container per test.
type Suite struct {
	Pool     *pgxpool.Pool
	teardown func()
}

// NewSuite starts a PostgreSQL 17 container, runs all migrations, and returns
// a Suite ready for use. Call Suite.Teardown() in TestMain after m.Run().
func NewSuite() (*Suite, error) {
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("testdb"),
		tcpostgres.WithUsername("testuser"),
		tcpostgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
				wait.ForListeningPort("5432/tcp"),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("start postgres container: %w", err)
	}

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = ctr.Terminate(ctx)
		return nil, fmt.Errorf("get connection string: %w", err)
	}

	if err = applyMigrations(connStr); err != nil {
		_ = ctr.Terminate(ctx)
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		_ = ctr.Terminate(ctx)
		return nil, fmt.Errorf("create pool: %w", err)
	}

	return &Suite{
		Pool: pool,
		teardown: func() {
			pool.Close()
			_ = ctr.Terminate(ctx)
		},
	}, nil
}

// Teardown shuts down the container and closes the pool. Call in TestMain.
func (s *Suite) Teardown() { s.teardown() }

// applyMigrations runs all SQL migrations against the given connection string.
// Colima (and some Docker Desktop setups) only forward ports on 127.0.0.1, not ::1,
// so we replace "localhost" with "127.0.0.1" to avoid IPv6 resolution failures.
func applyMigrations(connStr string) error {
	connStr = strings.ReplaceAll(connStr, "localhost", "127.0.0.1")
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("runtime.Caller failed")
	}

	migsDir := filepath.Join(filepath.Dir(filename), "..", "..", "..", "migrations")
	migsURL := "file://" + filepath.ToSlash(migsDir)

	m, err := migrate.New(migsURL, connStr)
	if err != nil {
		return err
	}
	defer m.Close()

	if err = m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// NewPostgresPool is kept for single-test usage (e.g. E2E tests that need
// a fresh isolated DB). Prefer Suite for repository tests.
func NewPostgresPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("testdb"),
		tcpostgres.WithUsername("testuser"),
		tcpostgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
				wait.ForListeningPort("5432/tcp"),
			),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	require.NoError(t, applyMigrations(connStr))

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	return pool
}
