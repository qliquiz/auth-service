package config

import (
	"auth-service/internal/postgres"
	"auth-service/internal/redis"
	"log"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env      string            `yaml:"env" env:"ENV" env-required:"true"`
	GRPC     GRPCConfig        `yaml:"grpc"`
	Gateway  GatewayConfig     `yaml:"gateway"`
	JWT      JWTConfig         `yaml:"jwt"`
	Security SecurityConfig    `yaml:"security"`
	Redis    redis.RedConfig   `yaml:"redis"`
	DB       postgres.DbConfig `yaml:"db"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port" env:"GRPC_PORT" env-default:"8081"`
	Timeout time.Duration `yaml:"timeout" env:"GRPC_TIMEOUT" env-default:"5s"`
}

type GatewayConfig struct {
	Port        int    `yaml:"port" env:"GATEWAY_PORT" env-default:"8080"`
	// GRPCTLSCert is the path to the gRPC server's TLS certificate file.
	// When set, the gateway connects to the gRPC backend over TLS.
	// Leave empty for local/dev single-host deployments (insecure loopback).
	GRPCTLSCert string `yaml:"grpc_tls_cert" env:"GATEWAY_GRPC_TLS_CERT" env-default:""`
}

type JWTConfig struct {
	Secret     string        `yaml:"secret" env:"JWT_SECRET" env-required:"true"`
	AccessTTL  time.Duration `yaml:"access_ttl" env:"JWT_ACCESS_TTL" env-default:"15m"`
	RefreshTTL time.Duration `yaml:"refresh_ttl" env:"JWT_REFRESH_TTL" env-default:"720h"`
}

// SecurityConfig groups brute-force and rate-limit tunables.
type SecurityConfig struct {
	BruteForce BruteForceConfig `yaml:"brute_force"`
	RateLimit  RateLimitConfig  `yaml:"rate_limit"`
}

// BruteForceConfig controls per-account failed-login tracking.
type BruteForceConfig struct {
	// MaxAttempts is the number of consecutive failures that trigger a lockout.
	MaxAttempts int `yaml:"max_attempts" env:"BRUTE_FORCE_MAX_ATTEMPTS" env-default:"5"`
	// Window is the rolling window over which failures are counted.
	Window time.Duration `yaml:"window" env:"BRUTE_FORCE_WINDOW" env-default:"15m"`
	// LockoutTTL is how long the account stays locked after the threshold is reached.
	LockoutTTL time.Duration `yaml:"lockout_ttl" env:"BRUTE_FORCE_LOCKOUT_TTL" env-default:"15m"`
}

// RateLimitConfig controls per-IP request throttling.
type RateLimitConfig struct {
	// GlobalRPM is the maximum requests per minute per IP across all endpoints.
	GlobalRPM int `yaml:"global_rpm" env:"RATE_LIMIT_GLOBAL_RPM" env-default:"300"`
	// LoginRPM is the stricter limit applied to Login and Register only.
	LoginRPM int `yaml:"login_rpm" env:"RATE_LIMIT_LOGIN_RPM" env-default:"20"`
}

func MustLoad() *Config {
	var cfg Config

	err := cleanenv.ReadEnv(&cfg)
	if err != nil {
		log.Fatalf("couldn't read the configuration: %v", err)
	}

	return &cfg
}
