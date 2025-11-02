#!/bin/bash

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║           Stv0r Messenger - Restart Script                       ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

# Остановка всех процессов
echo "⏹️  Останавливаю все процессы..."
killall -9 node pnpm tsx 2>/dev/null || true
sleep 2

# Запуск relay
echo "🚀 Запускаю Relay Server..."
cd /Users/ilaszajsenbaev/ilyazh-messenger

NODE_ENV=development \
HOST=0.0.0.0 \
PORT=3001 \
LOG_LEVEL=info \
STORAGE_TYPE=postgres \
DATABASE_URL="postgresql://postgres.uppanfnstjeybiseolmo:Ilyas228003@aws-1-eu-central-1.pooler.supabase.com:5432/postgres?sslmode=no-verify" \
JWT_SECRET="0jb8vV95MkIvsRfECDyXKDmpOl+qwapI+5fhIWSL4xC2LSYLSUsAUnloktqP5PQP" \
ALLOWED_ORIGINS="http://localhost:3000,http://localhost:3002,http://127.0.0.1:3000" \
ALLOW_DEV_AUTOCREATE=1 \
node apps/relay/dist/index.js > /tmp/relay.log 2>&1 &

RELAY_PID=$!
echo "   ✅ Relay PID: $RELAY_PID"

sleep 3

# Проверка relay
if curl -s http://localhost:3001/healthz > /dev/null; then
    echo "   ✅ Relay запущен: http://localhost:3001"
    curl -s http://localhost:3001/healthz
    echo ""
else
    echo "   ❌ Relay не запустился! Логи:"
    tail -20 /tmp/relay.log
    exit 1
fi

echo ""

# Запуск frontend
echo "🌐 Запускаю Web Frontend..."
cd apps/web
pnpm dev > /tmp/web.log 2>&1 &

WEB_PID=$!
echo "   ✅ Frontend PID: $WEB_PID"

sleep 5

# Проверка frontend
if curl -s http://localhost:3002 > /dev/null 2>&1; then
    echo "   ✅ Frontend запущен: http://localhost:3002"
else
    echo "   ⚠️  Frontend запускается... (может занять 10-20 секунд)"
    echo "   Проверьте через: curl http://localhost:3002"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                         ✅ ЗАПУЩЕНО                               ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Relay:    http://localhost:3001                                 ║"
echo "║  Frontend: http://localhost:3002                                 ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Логи:"
echo "   Relay:    tail -f /tmp/relay.log"
echo "   Frontend: tail -f /tmp/web.log"
echo ""
echo "🛑 Остановка:"
echo "   killall -9 node"
echo ""
