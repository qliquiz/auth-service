package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type RedConfig struct {
	Host     string `env:"REDIS_HOST" env-default:"localhost"`
	Port     int    `env:"REDIS_PORT" env-default:"6379"`
	Password string `env:"REDIS_PASSWORD"`
}

func New(ctx context.Context, cfg RedConfig) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       0,
	})

	if _, err := client.Ping(ctx).Result(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return client, nil
}
