ifneq (,$(wildcard ./.env))
    include .env
    export
endif

.PHONY: proto lint compose build run run-with-db-in-docker db migrate-up migrate-down clean test test-integration test-e2e test-cover

proto:
	@echo "generating proto files..."
	@mkdir -p gen/api docs
	@protoc \
     		-I api/auth \
     		-I api \
     		-I . \
     		--go_out=gen/api --go_opt=paths=source_relative \
     		--go-grpc_out=gen/api --go-grpc_opt=paths=source_relative \
			--grpc-gateway_out=gen/api --grpc-gateway_opt=paths=source_relative \
			--openapiv2_out=docs \
     		auth.proto
	@echo "proto files generated successfully."

lint:
	@echo "running linter..."
	@golangci-lint run -v

compose:
	@echo "running docker compose..."
	@docker-compose up --build -d

build:
	@echo "building the application..."
	@go build -o ./bin/auth-service ./cmd/auth-service

run: build compose
	@echo "running the application..."
	@./bin/auth-service

db:
	@echo "upping the DB in Docker..."
	@docker-compose up --build -d db

migrate-up:
	@echo "applying migrations..."
	@go run ./cmd/migrator \
		--migrations-path=./migrations \
		--command=up

migrate-down:
	@echo "rolling the latest migration back..."
	@go run ./cmd/migrator \
		--migrations-path=./migrations \
		--command=down

# Detect Docker socket at shell time (supports Docker Desktop, Colima, and Linux).
DOCKER_ENV = DOCKER_HOST=$$([ -S /var/run/docker.sock ] && echo unix:///var/run/docker.sock || echo unix://$$HOME/.colima/default/docker.sock) TESTCONTAINERS_RYUK_DISABLED=true

test:
	@echo "running unit tests..."
	@go test -race -count=1 ./...

test-integration:
	@echo "running integration tests (requires Docker)..."
	@$(DOCKER_ENV) go test -race -count=1 -tags=integration -timeout=180s -p=1 ./internal/repository/...

test-e2e:
	@echo "running e2e tests (requires Docker)..."
	@$(DOCKER_ENV) go test -race -count=1 -tags=integration,e2e -timeout=180s ./tests/e2e/...

test-all: test test-integration test-e2e

test-cover:
	@echo "running tests with coverage..."
	@go test -race -count=1 -coverprofile=tests/coverage.out ./...
	@go tool cover -html=tests/coverage.out -o tests/coverage.html
	@echo "coverage report → coverage.html"

clean:
	@echo "cleaning up..."
	@rm -rf ./gen ./bin ./tests/coverage.out ./tests/coverage.html
