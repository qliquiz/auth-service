# План разработки сервиса

## Фаза 1 — Core Auth (основа всего)

- Реализация Register / Login / ValidateToken
- Хэширование паролей через argon2id (bcrypt морально устарел)
- Access token (JWT, короткоживущий, ~15 мин) + Refresh token (непрозрачный UUID, хранится в Redis)
- Refresh token rotation — при каждом обновлении старый инвалидируется
- Полноценный UserRepository: Create, GetByEmail, GetByID
- gRPC status codes с правильными кодами ошибок (NOT_FOUND, ALREADY_EXISTS, UNAUTHENTICATED)

## Фаза 2 — Сессии и мультиплатформенность

Вот здесь ключевое отличие от "только для веба":

- Device sessions — каждый refresh token привязан к устройству (device_id, user_agent, ip, last_used_at)
- Отдельная таблица sessions в PostgreSQL
- Метод ListSessions — пользователь видит все активные устройства
- Метод RevokeSession / RevokeAllSessions — выход с конкретного или всех устройств
- Web получает httpOnly cookie, мобайл/десктоп — Bearer token в заголовке — один сервис, разная доставка

## Фаза 3 — Безопасность

- Rate limiting на уровне interceptor (gRPC) + middleware (gateway) — через Redis
- Защита от брутфорса: счётчик неудачных попыток в Redis с exponential backoff
- Account lockout после N попыток
- Audit log — таблица audit_events (кто, что, когда, с какого IP)
- Валидация входных данных (email format, password strength)
- Interceptor для логирования всех запросов

## Фаза 4 — MFA и OAuth2

- TOTP (Google Authenticator, Authy) — работает на всех платформах
- OAuth2 Consumer — "войти через Google / GitHub"
- Опционально: API keys для machine-to-machine (серверные интеграции без пользователя)

## Фаза 5 — Production readiness

- Metrics (Prometheus) — latency, error rates, active sessions
- Tracing (OpenTelemetry)
- Health checks (/healthz, /readyz)
- Unit + integration тесты
- CI/CD (GitHub Actions)