ifneq (,$(wildcard ./.env))
    include .env
    export
endif

.PHONY: proto lint compose build run run-with-db-in-docker db migrate-up migrate-down clean

proto:
	@echo "generating proto files..."
	@mkdir -p gen/api
	@protoc \
     		-I api/auth \
     		-I api \
     		-I . \
     		--go_out=gen/api --go_opt=paths=source_relative \
     		--go-grpc_out=gen/api --go-grpc_opt=paths=source_relative \
			--grpc-gateway_out=gen/api --grpc-gateway_opt=paths=source_relative \
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

run: build migrate-up
	@echo "running the application..."
	@./bin/auth-service

run-with-db-in-docker: build db migrate-up
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

clean:
	@echo "cleaning up..."
	@rm -rf ./gen ./bin
