package config

import (
	"auth-service/internal/postgres"
	"auth-service/internal/redis"
	"log"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env     string            `yaml:"env" env:"ENV" env-required:"true"`
	GRPC    GRPCConfig        `yaml:"grpc"`
	Gateway GatewayConfig     `yaml:"gateway"`
	Redis   redis.RedConfig   `yaml:"redis"`
	DB      postgres.DbConfig `yaml:"db"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port" env:"GRPC_PORT" env-default:"8081"`
	Timeout time.Duration `yaml:"timeout" env:"GRPC_TIMEOUT" env-default:"5s"`
}

type GatewayConfig struct {
	Port int `yaml:"port" env:"GATEWAY_PORT" env-default:"8080"`
}

func MustLoad() *Config {
	var cfg Config

	err := cleanenv.ReadEnv(&cfg)
	if err != nil {
		log.Fatalf("couldn't read the configuration: %v", err)
	}

	return &cfg
}
