FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git make
WORKDIR /app
COPY go.mod go.sum ./

RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /app/bin/migrator \
    ./cmd/migrator/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /app/bin/auth-service \
    main.go

FROM alpine:latest AS runtime
RUN apk --no-cache add ca-certificates tzdata

RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser
WORKDIR /app

COPY --from=builder /app/bin/auth-service /app/auth-service
COPY --from=builder /app/bin/migrator /app/migrator

COPY --from=builder /app/migrations /app/migrations

RUN chown -R appuser:appuser /app
USER appuser

FROM runtime AS auth-service
EXPOSE 8080 8082
ENTRYPOINT ["./auth-service"]

FROM runtime AS migrator
ENTRYPOINT ["./migrator"]
