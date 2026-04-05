# Auth Service

Сервис аутентификации и авторизации. Создан на основе архитектуры `order-manager`.

## Структура проекта

- `api/auth/auth.proto`: Определение gRPC/HTTP контрактов.
- `cmd/auth-service/main.go`: Точка входа в приложение.
- `cmd/migrator/main.go`: Утилита для применения миграций БД.
- `internal/config/`: Загрузка конфигурации из `.env`.
- `internal/postgres/`: Подключение к PostgreSQL (pgx pool).
- `internal/redis/`: Подключение к Redis.
- `internal/lib/logger/`: "Красивое" логирование в консоль.
- `migrations/`: SQL миграции для создания таблиц (`users`).

## Как запустить

1. **Поднять инфраструктуру (БД и Redis)**:
   ```bash
   make db
   ```

2. **Сгенерировать gRPC код**:
   ```bash
   make proto
   ```

3. **Применить миграции**:
   ```bash
   make migrate-up
   ```

4. **Запустить локально**:
   ```bash
   go run main.go
   ```

## Переменные окружения (.env)

- `GRPC_PORT`: Порт для gRPC (по умолчанию 8082).
- `GATEWAY_PORT`: Порт для HTTP-шлюза (по умолчанию 8080).
- `POSTGRES_HOST/PORT/DB/USER/PASSWORD`: Настройки подключения к БД.
