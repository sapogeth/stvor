# Vercel Setup Guide - Railway Relay Integration

## Проблема

Запросы к `/api/relay/*` возвращают HTML (404 от Vercel) вместо JSON от Railway Relay сервера.

**Ошибка:** `Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

## Причина

1. ❌ В `next.config.mjs` не были настроены `rewrites` для проксирования
2. ❌ В `vercel.json` не были указаны переменные окружения для Railway URL
3. ❌ API Route Handlers (`apps/web/app/api/relay/[...path]/route.ts`) вызывались, но не знали куда проксировать

## Решение

### 1. Обновлены файлы конфигурации

#### `next.config.mjs`
```javascript
async rewrites() {
  const relayUrl = process.env.RELAY_BASE_URL || process.env.RELAY_INTERNAL_URL || 'http://localhost:3001';
  
  return [
    {
      source: '/api/relay/:path*',
      destination: `${relayUrl}/:path*`,
    },
  ];
}
```

#### `vercel.json`
```json
{
  "env": {
    "RELAY_BASE_URL": "@relay_base_url",
    "RELAY_INTERNAL_URL": "@relay_internal_url"
  }
}
```

### 2. Настройка Vercel Secrets

Зайдите в Vercel Dashboard → Your Project → Settings → Environment Variables

Добавьте следующие переменные:

#### Production Environment

| Variable Name | Value | Environment |
|--------------|-------|-------------|
| `RELAY_BASE_URL` | `https://your-relay.railway.app` | Production |
| `RELAY_INTERNAL_URL` | `https://your-relay.railway.app` | Production |

**Важно:** Замените `your-relay.railway.app` на актуальный URL вашего Railway Relay сервера.

#### Preview & Development Environments

| Variable Name | Value | Environment |
|--------------|-------|-------------|
| `RELAY_BASE_URL` | `http://localhost:3001` | Preview, Development |
| `RELAY_INTERNAL_URL` | `http://localhost:3001` | Preview, Development |

### 3. Использование Vercel Secrets (опционально)

Для более безопасной настройки можно использовать Vercel Secrets:

```bash
# Создайте секрет
vercel secrets add relay_base_url https://your-relay.railway.app
vercel secrets add relay_internal_url https://your-relay.railway.app

# Секреты уже добавлены в vercel.json как @relay_base_url и @relay_internal_url
```

### 4. Получение Railway URL

Зайдите в Railway Dashboard:
1. Откройте проект **Relay Server**
2. Перейдите в **Settings** → **Domains**
3. Скопируйте **Public URL** (например, `https://ilyazh-relay-production.up.railway.app`)

### 5. Проверка настройки

После деплоя проверьте работу:

```bash
# Проверьте health endpoint через прокси
curl https://stvor.xyz/api/relay/healthz

# Должен вернуть JSON (не HTML):
{
  "status": "ok",
  "ready": true,
  "version": "0.8.0",
  "relayPublicKey": "..."
}
```

## Архитектура запросов

### Browser → Vercel → Railway

```
Browser (stvor.xyz)
  ↓ fetch('/api/relay/directory/username')
  ↓
Next.js Rewrite Rule (next.config.mjs)
  ↓ proxy to process.env.RELAY_BASE_URL
  ↓
Railway Relay Server
  ↓ https://your-relay.railway.app/directory/username
  ↓
Response JSON → Next.js → Browser
```

### Fallback: API Route Handlers

Если rewrites не сработают, запрос попадёт в API Route Handler:
- `apps/web/app/api/relay/[...path]/route.ts`
- Проксирует на `process.env.RELAY_BASE_URL`
- Возвращает JSON или 502 при недоступности Relay

## Переменные окружения в коде

### Client-side (браузер)
```typescript
// apps/web/lib/config.ts
export function getRelayBaseUrl(): string {
  if (typeof window !== 'undefined') {
    return '/api/relay'; // ВСЕГДА через прокси
  }
  return process.env.RELAY_INTERNAL_URL || 'http://localhost:3001';
}
```

### Server-side (Next.js API Routes)
```typescript
// apps/web/app/api/relay/[...path]/route.ts
const RELAY_URL =
  process.env.RELAY_BASE_URL ||
  process.env.RELAY_INTERNAL_URL ||
  'http://localhost:3001';
```

## Troubleshooting

### Ошибка: Still getting HTML instead of JSON

**Проверьте:**
1. Переменные окружения установлены в Vercel Dashboard
2. Vercel project redeploy после добавления переменных
3. Railway Relay сервер доступен и отвечает на `GET /healthz`

**Команды для отладки:**
```bash
# Проверьте Railway Relay напрямую
curl https://your-relay.railway.app/healthz

# Проверьте через Vercel прокси
curl https://stvor.xyz/api/relay/healthz

# Проверьте логи Vercel
vercel logs --follow
```

### Ошибка: 502 Bad Gateway

**Причина:** Relay сервер недоступен или перезапускается

**Решение:**
1. Проверьте статус Railway deployment
2. Убедитесь, что Railway сервер прошёл health check
3. Проверьте Railway logs для ошибок запуска

### Ошибка: CORS blocked

**Причина:** Railway Relay не добавил `stvor.xyz` в ALLOWED_ORIGINS

**Решение:**
Убедитесь, что в `apps/relay/src/index.ts` добавлены production origins:
```typescript
const ALLOWED_ORIGINS = [
  'https://stvor.xyz',
  'https://www.stvor.xyz',
  // ...
];
```

## Checklist перед Production

- [ ] `RELAY_BASE_URL` установлен в Vercel (Production)
- [ ] `RELAY_INTERNAL_URL` установлен в Vercel (Production)
- [ ] Railway Relay доступен по HTTPS
- [ ] Railway Relay добавил production origins в CORS
- [ ] Vercel project redeploy выполнен после настройки
- [ ] `GET /api/relay/healthz` возвращает JSON (не HTML)
- [ ] `POST /api/relay/directory/username` возвращает 200 OK

## Связанные файлы

- `apps/web/next.config.mjs` - Next.js rewrites configuration
- `vercel.json` - Vercel deployment settings
- `apps/web/lib/config.ts` - Relay URL resolution logic
- `apps/web/app/api/relay/[...path]/route.ts` - Fallback proxy handler
- `apps/relay/src/index.ts` - Railway Relay CORS configuration
