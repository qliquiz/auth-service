# Auth Service

#### Микросервис для аутентификации и авторизации пользователей.

---

## Технологический стек

- **Язык:** Go 1.25+
- **База данных:** PostgreSQL + Redis (хранение сессий/токенов)
- **API:** gRPC, HTTP (gRPC-Gateway)
- **Контейнеризация:** Docker, Docker Compose
- **Сборка и управление:** Makefile
- **Миграции:** golang-migrate

## Запуск и настройка

### Предварительные требования

- **Docker** и **Docker Compose**
- **Go** (версия 1.25+)
- **Make**
- **protoc** (для генерации кода из `.proto` файлов)

---

### 1. Конфигурация

Вся конфигурация осуществляется через переменные окружения.

1. Создайте файл `.env` в корне проекта:
   ```bash
   cp .env.example .env # Если есть пример, или создайте вручную
   ```
2. Настройте параметры подключения:

**Пример файла `.env`:**

```env
ENV=local # Среда выполнения (local, dev, prod)
GRPC_PORT=8082 # Порт gRPC сервера
GRPC_TIMEOUT=5s
GATEWAY_PORT=8080 # Порт HTTP-шлюза

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=auth_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
```

**Важно:** Для запуска внутри Docker установите `POSTGRES_HOST=db` и `REDIS_HOST=redis`.

---

### 2. Быстрый старт (Docker)

Запуск всей инфраструктуры и приложения в контейнерах:

```bash
make compose
```

Эта команда соберет образы, запустит БД, Redis, применит миграции и запустит сервис.

---

### 3. Локальная разработка

Если вы хотите запускать Go-приложение локально, а инфраструктуру в Docker:

1. **Запустите БД и Redis**:
    ```bash
    make db
    ```
2. **Примените миграции**:
    ```bash
    make migrate-up
    ```
3. **Сгенерируйте gRPC код**:
    ```bash
    make proto
    ```
4. **Запустите приложение**:
    ```bash
    go run main.go
    ```

---

## Взаимодействие с API

### Пример HTTP-запроса (cURL)

Регистрация нового пользователя:

```bash
curl -X POST http://localhost:8080/v1/auth/register \
-H "Content-Type: application/json" \
-d '{"email": "user@example.com", "password": "securepassword"}'
```

### Пример gRPC-запроса (grpcurl)

Вход в систему:

```bash
grpcurl -plaintext -d '{"email": "user@example.com", "password": "securepassword"}' \
localhost:8082 api.AuthService/Login
```

---

## Команды Makefile

- `make proto`: Генерирует Go-код из `.proto` файлов.
- `make compose`: Запускает всё окружение через Docker Compose.
- `make db`: Запускает только PostgreSQL и Redis в Docker.
- `make migrate-up`: Применяет миграции базы данных.
- `make migrate-down`: Откатывает последнюю миграцию.
- `make build`: Собирает бинарный файл приложения.
- `make clean`: Удаляет сгенерированные файлы и бинарники.
