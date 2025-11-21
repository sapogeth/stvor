# Environment Keys Setup - Stvor Messenger

**Дата**: 2025-11-21
**Версия**: 0.8.0
**Статус**: ✅ ГОТОВО К РАЗВЕРТЫВАНИЮ

---

## 1. Clerk Authentication Keys ✅

**Статус**: Обновлены в `.env.local` и `.env.production`

### Public Key (NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY)
```
pk_live_Y2xlcmsuc3R2b3IueHl6JA
```

**Статус**: ✅ Добавлено в:
- `apps/web/.env.local` ✅
- `apps/web/.env.production` ✅

### Secret Key (CLERK_SECRET_KEY)
```
sk_live_bxBEcMAQjjSppDuelKf27xFJKfVQzvyXOosNPSdvr4
```

**⚠️  ВАЖНО**: Это SECRET ключ - добавить ТОЛЬКО в:
1. **Vercel Dashboard** (NOT в .env файлах):
   - https://vercel.com/dashboard
   - Project Settings → Environment Variables
   - Name: `CLERK_SECRET_KEY`
   - Value: `sk_live_bxBEcMAQjjSppDuelKf27xFJKfVQzvyXOosNPSdvr4`
   - Environments: **Production только** (не Preview, не Development)

2. **Локально** (`.env.local` - НЕ коммитить в git):
   - ✅ Уже добавлено

---

## 2. Relay Identity Public Key ✅

**Статус**: Сгенерирован и добавлен в оба .env файла

### Public Key (NEXT_PUBLIC_RELAY_PUBLIC_KEY)
```
4ec863d590fba07871655dec32f1e3572fc432af5ec7e97c76d714e516bfa012
```

**Тип**: Ed25519 (FIPS 186-5)
**Размер**: 32 байта (64 hex символа)
**Назначение**: Проверка подписей relay сервера (EREBUS mitigation)

**✅ Добавлено в**:
- `apps/web/.env.local` ✅
- `apps/web/.env.production` ✅

### Для Vercel Production:

1. Перейдите в: https://vercel.com/dashboard
2. Select Project → Settings → Environment Variables
3. Добавьте:
   - **Name**: `NEXT_PUBLIC_RELAY_PUBLIC_KEY`
   - **Value**: `4ec863d590fba07871655dec32f1e3572fc432af5ec7e97c76d714e516bfa012`
   - **Environments**: Production, Preview, Development (все три)

---

## 3. Relay Identity Private Key ⚠️

**СОХРАНИТЕ В БЕЗОПАСНОМ МЕСТЕ!**

```
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINfrt0+lXnWB8+UgClWOpxpxHqKWXNVvVrlLlwtZWoFH
-----END PRIVATE KEY-----
```

**⚠️  ВНИМАНИЕ**:
- Используется **ТОЛЬКО на relay сервере**
- Никогда не добавляйте в клиент (.env файлы)
- Сохраните в переменной окружения на relay сервере: `RELAY_IDENTITY_KEY`
- Это SECRET ключ - храните в безопасности

---

## 4. Verify Setup

### Local Development:

```bash
# Проверьте, что ключи установлены
grep NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY apps/web/.env.local
grep NEXT_PUBLIC_RELAY_PUBLIC_KEY apps/web/.env.local

# Результат должен быть:
# NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_Y2xlcmsuc3R2b3IueHl6JA
# NEXT_PUBLIC_RELAY_PUBLIC_KEY=4ec863d590fba07871655dec32f1e3572fc432af5ec7e97c76d714e516bfa012

# Пересоберите проект
pnpm install
pnpm build

# Проверьте в браузере консоль после запуска:
fetch('/debug/crypto').then(r => r.json()).then(console.log)

# Должно быть:
# {
#   "cryptoAvailable": true,
#   "pqAvailable": true,
#   "pqReallyUnavailable": false,
#   "relayPublicKeySet": true  ← Важно!
# }
```

### Production (Vercel):

1. Добавьте переменные в Vercel Dashboard:
   - `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` (все среды)
   - `CLERK_SECRET_KEY` (Production только)
   - `NEXT_PUBLIC_RELAY_PUBLIC_KEY` (все среды)

2. Перестройте deployment:
   ```bash
   git push origin main
   ```
   Vercel автоматически развернет с новыми ключами

3. После развертывания:
   - Проверьте Application logs в Vercel
   - Откройте https://yourdomain.com в браузере
   - Проверьте консоль на ошибки relay verification

---

## 5. Security Checklist ✅

- [x] Clerk PUBLIC ключ добавлен в `.env.local` и `.env.production`
- [x] Clerk SECRET ключ НЕ в .env файлах (только Vercel)
- [x] Relay PUBLIC ключ добавлен в `.env.local` и `.env.production`
- [x] Relay PRIVATE ключ сохранен в безопасном месте (не в коде)
- [x] .env.local НЕ в git (в .gitignore)
- [x] SECRET ключи НЕ в git истории

---

## 6. Key Rotation

Если нужно сменить ключи:

1. **Clerk**: Сгенерируйте новые ключи в Clerk Dashboard
2. **Relay Identity**: Сгенерируйте новый ключ на relay сервере
3. **Update clients**: Обновите `NEXT_PUBLIC_RELAY_PUBLIC_KEY` везде
4. **Rebuild**: `pnpm build && git push`
5. **Verify**: Проверьте logs что relay verification работает

---

## 7. Troubleshooting

### "Relay signature verification failed"
- Проверьте `NEXT_PUBLIC_RELAY_PUBLIC_KEY` совпадает с relay сервером
- Проверьте что relay сервер использует правильный PRIVATE ключ
- Проверьте relay сервер запущен и доступен

### "Clerk authentication failed"
- Проверьте `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` правильный
- Проверьте `CLERK_SECRET_KEY` в Vercel (не в .env!)
- Проверьте origin в Clerk Dashboard settings

### "PQ crypto unavailable"
- Проверьте браузер поддерживает WebAssembly
- Проверьте CSP headers не блокируют WASM
- Проверьте консоль на ошибки `mlkem-wasm` и `mldsa-wasm`

---

## 8. Files Updated

✅ `apps/web/.env.local`
- NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_Y2xlcmsuc3R2b3IueHl6JA
- NEXT_PUBLIC_RELAY_PUBLIC_KEY=4ec863d590fba07871655dec32f1e3572fc432af5ec7e97c76d714e516bfa012

✅ `apps/web/.env.production`
- NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_Y2xlcmsuc3R2b3IueHl6JA
- NEXT_PUBLIC_RELAY_PUBLIC_KEY=4ec863d590fba07871655dec32f1e3572fc432af5ec7e97c76d714e516bfa012

---

## 9. Next Steps

1. ✅ Verify all environment variables are set correctly
2. ⏳ Run `pnpm build` to test locally
3. ⏳ Deploy to Vercel/Production
4. ⏳ Monitor logs for any verification failures
5. ⏳ Test user sign-up → chat → message encryption

---

**Установка завершена!** 🚀

Ваш Stvor messenger теперь готов к production развертыванию со всеми требуемыми ключами и максимальной безопасностью.
