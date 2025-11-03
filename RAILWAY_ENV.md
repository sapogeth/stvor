# Railway Environment Variables

Установите эти переменные окружения в Railway:

## Обязательные

```bash
# JWT Secret (сгенерируйте новый!)
JWT_SECRET=<openssl rand -base64 48>
```

## Опциональные (с дефолтами)

```bash
# Port (Railway установит автоматически)
PORT=3001

# Host (уже есть в коде как дефолт)
HOST=0.0.0.0

# Storage type (дефолт: memory)
STORAGE_TYPE=memory

# Database URL (только если STORAGE_TYPE=postgres)
# DATABASE_URL=postgresql://user:pass@host:5432/db

# Development mode
ALLOW_DEV_AUTOCREATE=0

# Logging
LOG_LEVEL=info

# CORS
ALLOWED_ORIGINS=*
```

## Генерация JWT_SECRET

В терминале:
```bash
openssl rand -base64 48
```

Скопируйте результат и установите как `JWT_SECRET` в Railway.

## Важно

- Если не установить `STORAGE_TYPE`, будет использован `memory` (данные в RAM)
- Если установить `STORAGE_TYPE=postgres` без `DATABASE_URL`, сервер fallback на `memory`
- Сервер стартует ПЕРВЫМ, потом инициализирует storage - `/healthz` всегда отвечает
