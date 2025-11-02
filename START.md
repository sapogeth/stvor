# 🚀 Быстрый Старт Stv0r Messenger

## ✅ Текущий Статус

**Проект ЗАПУЩЕН на localhost:**
- ✅ **Relay Server:** http://localhost:3001 (работает)
- ⚠️ **Web Frontend:** http://localhost:3002 (нужны Clerk ключи)

---

## 🔑 Получить Clerk Ключи (2 минуты)

1. Откройте https://dashboard.clerk.com/sign-up
2. Создайте аккаунт
3. Создайте приложение (Create Application)
4. Скопируйте два ключа:
   ```
   NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_xxxxx...
   CLERK_SECRET_KEY=sk_test_xxxxx...
   ```
5. Откройте `apps/web/.env.local` и замените placeholder ключи

---

## 🔄 Перезапуск с Clerk Ключами

```bash
# Остановить все процессы
killall -9 node

# Запустить relay
cd /Users/ilaszajsenbaev/ilyazh-messenger
NODE_ENV=development \
STORAGE_TYPE=memory \
JWT_SECRET="0jb8vV95MkIvsRfECDyXKDmpOl+qwapI+5fhIWSL4xC2LSYLSUsAUnloktqP5PQP" \
ALLOWED_ORIGINS="http://localhost:3000,http://localhost:3002" \
ALLOW_DEV_AUTOCREATE=1 \
node apps/relay/dist/index.js > /tmp/relay.log 2>&1 &

# Подождать 3 секунды
sleep 3

# Запустить frontend
cd apps/web
pnpm dev

# Открыть в браузере
open http://localhost:3002
```

---

## 🧪 Проверка Работы

```bash
# Relay health
curl http://localhost:3001/healthz
# Ожидается: {"status":"ok","storage":"memory","version":"0.8.0"}

# Relay metrics
curl http://localhost:3001/metrics

# Frontend
open http://localhost:3002
```

---

## 🛑 Остановка

```bash
killall -9 node
```

---

## 📝 Файлы Конфигурации

- `apps/web/.env.local` - frontend env (редактируй Clerk ключи здесь)
- `apps/relay/.env` - relay env (уже настроен)
- `DEPLOY.md` - инструкции для production deployment

---

## 🔐 Безопасность

**✅ Все критичные файлы в .gitignore:**
- `.env`
- `.env.local`
- `.env.production`
- `apps/web/.env.local`
- `apps/relay/.env`

**НЕ коммитьте эти файлы в git!**

---

## 🚀 Следующие Шаги

1. Получить Clerk ключи → обновить `apps/web/.env.local`
2. Перезапустить с командами выше
3. Открыть http://localhost:3002
4. Зарегистрировать двух тестовых пользователей
5. Отправить зашифрованное сообщение
6. Проверить Safety Numbers

---

## 🆘 Проблемы?

**Frontend не загружается:**
- Проверьте Clerk ключи в `apps/web/.env.local`
- Убедитесь что ключи начинаются с `pk_test_` и `sk_test_`

**Relay не запускается:**
- Проверьте логи: `cat /tmp/relay.log`
- Убедитесь что порт 3001 свободен: `lsof -i :3001`

**Ошибка CORS:**
- Проверьте `ALLOWED_ORIGINS` включает `http://localhost:3002`
