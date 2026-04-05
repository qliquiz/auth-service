package auth

import (
	"auth-service/gen/api"
	"auth-service/internal/repository/user"
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

type AuthService struct {
	api.UnimplementedAuthServiceServer
	repo        *user.UserRepository
	redisClient *redis.Client
	log         *slog.Logger
	timeout     time.Duration
}

func New(
	repo *user.UserRepository,
	redisClient *redis.Client,
	log *slog.Logger,
	timeout time.Duration,
) *AuthService {
	return &AuthService{
		repo:        repo,
		redisClient: redisClient,
		log:         log,
		timeout:     timeout,
	}
}

func Register(gRPC *grpc.Server, authService *AuthService) {
	api.RegisterAuthServiceServer(gRPC, authService)
}

func (s *AuthService) Register(ctx context.Context, req *api.RegisterRequest) (*api.RegisterResponse, error) {
	// TODO: Implement
	return &api.RegisterResponse{}, nil
}

func (s *AuthService) Login(ctx context.Context, req *api.LoginRequest) (*api.LoginResponse, error) {
	// TODO: Implement
	return &api.LoginResponse{}, nil
}

func (s *AuthService) ValidateToken(ctx context.Context, req *api.ValidateTokenRequest) (*api.ValidateTokenResponse, error) {
	// TODO: Implement
	return &api.ValidateTokenResponse{}, nil
}
