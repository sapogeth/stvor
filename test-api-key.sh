#!/bin/bash
# Тест relay с новым API ключом

API_KEY="8n+jACwF42aAgYbOvHeDAi2IcSghGsIvra4mUHZr3E4="
RELAY_URL="https://ilyazhrelay-production.up.railway.app"

echo "Testing Railway relay with API key..."
echo ""

# 1. Healthcheck (без ключа)
echo "1. Healthcheck:"
curl -s "$RELAY_URL/healthz" | jq . || echo "No jq installed"
echo ""

# 2. Directory GET (с ключом)
echo "2. Directory GET (должен вернуть 404 для несуществующего юзера):"
curl -s -H "Authorization: Bearer $API_KEY" \
  "$RELAY_URL/directory/nonexistentuser123" \
  | jq . || echo "Response printed above"
echo ""

# 3. Directory GET без ключа (должен вернуть 403)
echo "3. Directory GET без ключа (должен вернуть 403):"
curl -s -w "HTTP: %{http_code}\n" \
  "$RELAY_URL/directory/testuser"
echo ""

echo "✅ Если видишь 404 в тесте 2 и 403 в тесте 3 - всё работает!"
