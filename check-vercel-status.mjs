#!/usr/bin/env node

/**
 * Check current Vercel deployment status
 * Shows what environment variables are currently set
 */

console.log('\n' + '='.repeat(80));
console.log('🔍 VERCEL PRODUCTION DEPLOYMENT STATUS');
console.log('='.repeat(80));

console.log('\n📋 ЧТО НУЖНО СДЕЛАТЬ:\n');

console.log('1️⃣  Открыть: https://vercel.com/dashboard');
console.log('2️⃣  Выбрать проект "stvor"');
console.log('3️⃣  Settings → Environment Variables');
console.log('4️⃣  ⚠️  Выбрать "Production" окружение');
console.log('5️⃣  Добавить две переменные:\n');

console.log('   ┌─ Переменная 1 ─────────────────────────────────┐');
console.log('   │ Name:  NEXT_PUBLIC_RELAY_URL                    │');
console.log('   │ Value: https://ilyazhrelay-production...       │');
console.log('   └─────────────────────────────────────────────────┘\n');

console.log('   ┌─ Переменная 2 ─────────────────────────────────┐');
console.log('   │ Name:  RELAY_BASE_URL                           │');
console.log('   │ Value: https://ilyazhrelay-production...       │');
console.log('   └─────────────────────────────────────────────────┘\n');

console.log('6️⃣  Нажать "Save"');
console.log('7️⃣  Нажать "Redeploy"');
console.log('8️⃣  Дождись статуса "Ready" (2-3 минуты)');

console.log('\n' + '='.repeat(80));
console.log('✅ ПРОВЕРКА ПОСЛЕ РЕДЕПЛОЯ:');
console.log('='.repeat(80));

console.log('\n1. Открой https://stvor.vercel.app');
console.log('2. Открой DevTools (F12) → Console');
console.log('3. Посмотри логи WebSocket подключения:');
console.log('   ✅ ДОЛЖНО быть: "Connecting to ws://ilyazhrelay-production..."');
console.log('   ❌ НЕ должно быть: "Connecting to ws://stvor-web.vercel.app:3001..."');

console.log('\n' + '='.repeat(80));
console.log('📊 ТЕКУЩИЙ СТАТУС (.env.production):');
console.log('='.repeat(80));

try {
  const fs = await import('fs');
  const envContent = fs.readFileSync('./apps/web/.env.production', 'utf8');
  const relayUrlMatch = envContent.match(/NEXT_PUBLIC_RELAY_URL=(.+)/);
  const baseUrlMatch = envContent.match(/RELAY_BASE_URL=(.+)/);

  if (relayUrlMatch) {
    console.log(`\n✅ NEXT_PUBLIC_RELAY_URL=${relayUrlMatch[1]}`);
  } else {
    console.log('\n❌ NEXT_PUBLIC_RELAY_URL не найден в .env.production');
  }

  if (baseUrlMatch) {
    console.log(`✅ RELAY_BASE_URL=${baseUrlMatch[1]}`);
  } else {
    console.log('❌ RELAY_BASE_URL не найден в .env.production');
  }
} catch (err) {
  console.error(`\n❌ Ошибка чтения .env.production: ${err.message}`);
}

console.log('\n' + '='.repeat(80));
console.log('\n⏰ Время на выполнение: ~5 минут\n');
