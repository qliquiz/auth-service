package app

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	rediscache "auth-service/internal/adapters/cache/redis"
	"auth-service/internal/adapters/hooks"
	pgstore "auth-service/internal/adapters/storage/postgres"
	jwtlib "auth-service/internal/adapters/token/jwt"
	"auth-service/internal/app/gateway"
	grpcApp "auth-service/internal/app/grpc"
	"auth-service/internal/config"
	"auth-service/internal/domain/ports"
	"auth-service/internal/interceptor"
	"auth-service/internal/lib/bruteforce"
	"auth-service/internal/lib/ratelimit"
	"auth-service/internal/postgres"
	"auth-service/internal/service/auth"
)

type App struct {
	GrpcApp    *grpcApp.App
	GatewayApp *gateway.App
}

func New(
	db *postgres.Database,
	redisClient *redis.Client,
	log *slog.Logger,
	grpcPort int,
	gatewayPort int,
	grpcTimeout time.Duration,
	jwtCfg config.JWTConfig,
	secCfg config.SecurityConfig,
	gatewayCfg config.GatewayConfig,
	env string,
) (*App, error) {
	uRepo := pgstore.NewUserRepository(db.Pool)
	sRepo := pgstore.NewSessionRepository(db.Pool)
	aRepo := pgstore.NewAuditRepository(db.Pool)

	tokenMgr, err := buildTokenManager(jwtCfg)
	if err != nil {
		return nil, fmt.Errorf("build token manager: %w", err)
	}

	cache := rediscache.New(redisClient)
	resetStore := rediscache.NewResetCache(redisClient)
	guard := bruteforce.New(
		redisClient,
		secCfg.BruteForce.MaxAttempts,
		secCfg.BruteForce.Window,
		secCfg.BruteForce.LockoutTTL,
	)

	service := auth.New(uRepo, sRepo, tokenMgr, cache, resetStore, aRepo, guard, hooks.NoOp{}, log, jwtCfg.RefreshTTL)

	globalLimiter := ratelimit.New(redisClient, secCfg.RateLimit.GlobalRPM, time.Minute)
	loginLimiter := ratelimit.New(redisClient, secCfg.RateLimit.LoginRPM, time.Minute)

	grpcApplication := grpcApp.New(service, log, grpcPort,
		grpc.ConnectionTimeout(grpcTimeout),
		grpc.ChainUnaryInterceptor(
			interceptor.Logging(log),
			interceptor.RateLimit(globalLimiter, loginLimiter, log),
		),
	)
	gatewayApplication := gateway.New(log, gatewayPort, grpcPort, gatewayCfg.GRPCTarget, gatewayCfg.GRPCTLSCert, env)

	return &App{
		GrpcApp:    grpcApplication,
		GatewayApp: gatewayApplication,
	}, nil
}

// buildTokenManager selects the JWT signing strategy from config.
// hs256 uses the shared secret from JWT_SECRET.
// rs256/es256 load a PEM private key from JWT_PRIVATE_KEY_PATH.
func buildTokenManager(cfg config.JWTConfig) (ports.AccessTokenManager, error) {
	switch cfg.Algorithm {
	case "", "hs256":
		return jwtlib.NewHS256Manager(cfg.Secret, cfg.AccessTTL), nil

	case "rs256":
		keyBytes, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read RSA key %q: %w", cfg.PrivateKeyPath, err)
		}
		priv, err := parseRSAKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA key: %w", err)
		}
		return jwtlib.NewRS256Manager(priv, cfg.AccessTTL), nil

	case "es256":
		keyBytes, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read ECDSA key %q: %w", cfg.PrivateKeyPath, err)
		}
		priv, err := parseECDSAKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse ECDSA key: %w", err)
		}
		return jwtlib.NewES256Manager(priv, cfg.AccessTTL), nil

	default:
		return nil, fmt.Errorf("unsupported JWT_ALGORITHM %q: must be hs256, rs256, or es256", cfg.Algorithm)
	}
}

// parseRSAKey decodes a PEM block and tries PKCS#1 then PKCS#8.
func parseRSAKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key (PKCS1/PKCS8): %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PEM key is not RSA (got %T)", key)
	}
	return rsaKey, nil
}

// parseECDSAKey decodes a PEM block and tries EC then PKCS#8.
func parseECDSAKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ECDSA private key (EC/PKCS8): %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PEM key is not ECDSA (got %T)", key)
	}
	return ecKey, nil
}
