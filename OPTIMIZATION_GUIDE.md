# Оптимизация производительности Stvor: Web Workers и Ленивая загрузка

## 📋 Обзор проблемы

Ваше приложение Stvor использует post-quantum криптографию (ML-KEM-768 + ML-DSA-65) и Argon2id для защиты. Однако эти операции выполняются в **Main Thread браузера**, что блокирует отрисовку UI и вызывает лаги на 2-5 секунд.

### Почему это происходит?

1. **Argon2id SENSITIVE**: Специально медленный режим для защиты от brute-force атак
   - Использует 256 MB памяти
   - Выполняет 4 итерации
   - Занимает 2-5 секунд на среднем ноутбуке

2. **ML-KEM-768 / ML-DSA-65**: Сложная математика на решетках
   - Инициализация WASM-модулей
   - Генерация ключей
   - Преобразование ключей

3. **Main Thread блокировка**: Когда криптографические операции выполняются в том же потоке, что и отрисовка UI, браузер не может обновлять экран.

---

## 🛠️ Решение: Web Workers + Ленивая загрузка

### Архитектура

```
┌─────────────────────────────────────────────┐
│         Main Thread (UI Rendering)          │
│  - React components                         │
│  - Event handling                           │
│  - DOM updates                              │
└────────────┬────────────────────────────────┘
             │ (fast communication via postMessage)
┌────────────▼────────────────────────────────┐
│       Worker Thread (Crypto Operations)     │
│  - Argon2id hashing                         │
│  - ML-KEM-768 key generation               │
│  - ML-DSA-65 signing                        │
│  - WASM module initialization              │
└─────────────────────────────────────────────┘
```

### Компоненты решения

#### 1. Web Worker (`crypto.worker.ts`)
Выполняет тяжелые криптографические операции в отдельном потоке.

```typescript
// apps/web/lib/workers/crypto.worker.ts
// Инициализирует WASM модули в отдельном потоке
// Генерирует ключи без блокировки Main Thread
// Результаты отправляются через postMessage
```

#### 2. Worker Manager (`crypto-worker-manager.ts`)
Управляет жизненным циклом Worker'а и очередью запросов.

```typescript
// apps/web/lib/workers/crypto-worker-manager.ts
const manager = getCryptoWorkerManager();
const identity = await manager.generateIdentity();
// Работает в отдельном потоке - Main Thread свободен!
```

#### 3. React Hook (`useCryptoWorker`)
Удобный Hook для использования Worker'а в компонентах.

```typescript
// Пример использования
const { generateIdentity, loading } = useCryptoWorker();
const identity = await generateIdentity();
```

#### 4. Ленивая загрузка PQ (`lazy-pq-loader.ts`)
Инициализирует PQ-модули только когда пользователь начинает чат.

```typescript
// Главная страница загружается быстро (без PQ)
// Чат-страница инициализирует PQ при входе
const { initialize } = useLazyPQ();
await initialize(); // Background loading
```

---

## 📊 Параметры Argon2id

### Текущие настройки (SENSITIVE)
```
memoryLimit: 256 MB
opsLimit: 4
Время: 2-5 секунд ❌ Слишком медленно для браузера
```

### Рекомендуемые настройки (MODERATE)
```typescript
memoryLimit: 64 MB     // 4x меньше памяти
opsLimit: 2            // 2x меньше итераций
Время: 500ms - 1.5s    // ✓ Приемлемо для пользователя
Защита: Хорошая        // Все еще защищает от GPU-атак
```

### Быстрые настройки (INTERACTIVE)
```
memoryLimit: 16 MB
opsLimit: 1
Время: 100-300ms
Защита: Базовая (⚠️ НЕ рекомендуется для production)
```

### Использование разных режимов по контексту

```typescript
import { getArgon2ModeForContext } from '@/lib/crypto/argon2-config';

// Регистрация: можно медленнее
const regMode = getArgon2ModeForContext('registration'); // MODERATE

// Логин: баланс
const loginMode = getArgon2ModeForContext('login'); // MODERATE

// Инициализация PQ: нужна скорость
const initMode = getArgon2ModeForContext('init'); // INTERACTIVE

// Восстановление устройства: максимальная безопасность
const recoveryMode = getArgon2ModeForContext('device-recovery'); // SENSITIVE
```

---

## 💻 Практические примеры

### Пример 1: Оптимизированная инициализация криптографии

**ПЛОХО (текущий код):**
```typescript
function Page() {
  // ❌ initializeCrypto() запускается при КАЖДОМ рендере!
  initializeCrypto();

  return <div>...</div>;
}
```

**ХОРОШО (оптимизировано):**
```typescript
function Page() {
  useEffect(() => {
    // ✓ initializeCrypto() запускается ОДИН раз при монтировании
    const initCrypto = async () => {
      const { initCryptoOnce } = await import('@/lib/crypto/init');
      await initCryptoOnce();
    };

    initCrypto();
  }, []); // <- Пустой массив зависимостей!

  return <div>...</div>;
}
```

### Пример 2: Использование Web Worker для генерации ключей

```typescript
'use client';

import { useCryptoWorker } from '@/lib/hooks/useCryptoWorker';

export function IdentityGenerator() {
  const { generateIdentity, loading, error } = useCryptoWorker();

  const handleGenerate = async () => {
    try {
      const identity = await generateIdentity();
      // Ключи сгенерированы в отдельном потоке!
      // Main Thread был свободен для отрисовки
      console.log('Identity generated:', identity);
    } catch (err) {
      console.error('Failed to generate identity:', err);
    }
  };

  return (
    <div>
      <button onClick={handleGenerate} disabled={loading}>
        {loading ? 'Generating keys...' : 'Generate Identity'}
      </button>
      {error && <p style={{ color: 'red' }}>{error.message}</p>}
    </div>
  );
}
```

### Пример 3: Ленивая загрузка PQ для чата

```typescript
'use client';

import { useLazyPQ } from '@/lib/lazy-pq-loader';

export function ChatPage({ chatId, username }) {
  const { state, error, initialize } = useLazyPQ();

  useEffect(() => {
    // Инициализируем PQ когда пользователь открывает чат
    // (а не при загрузке главной страницы)
    initialize();
  }, [initialize]);

  if (state === 'loading') {
    return <LoadingSpinner message="Setting up secure chat..." />;
  }

  if (state === 'error') {
    return <ErrorMessage error={error} />;
  }

  // state === 'ready'
  return <ChatUI chatId={chatId} username={username} />;
}
```

### Пример 4: Выбор режима Argon2id

```typescript
import { getArgon2Config, Argon2Mode } from '@/lib/crypto/argon2-config';

// В функции инициализации пользователя:
const mode = getArgon2Config(Argon2Mode.MODERATE);

// Использовать в Argon2id:
const derivedKey = await sodium.crypto_pwhash(
  keyLength,
  password,
  salt,
  mode.opsLimit,      // 2 вместо 4
  mode.memoryLimit,   // 64 MB вместо 256 MB
  sodium.crypto_pwhash_ALG_ARGON2ID13
);
```

---

## 🚀 План внедрения

### Шаг 1: Обновить главный layout
```typescript
// apps/web/app/layout.tsx
import { CryptoInitializerOptimized } from '@/components/CryptoInitializerOptimized';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        {/* Инициализирует классическую крипто, PQ - ленивая загрузка */}
        <CryptoInitializerOptimized lazyLoadPQ={true} />
        {children}
      </body>
    </html>
  );
}
```

### Шаг 2: Обновить чат-компонент
```typescript
// apps/web/app/chat/page.tsx
export default function ChatPage() {
  // При открытии чата инициализируем PQ
  const { initialize } = useLazyPQ();

  useEffect(() => {
    initialize(); // Загружается в фоне, не блокирует UI
  }, [initialize]);

  // ... остальной код
}
```

### Шаг 3: Настроить Argon2id параметры
```typescript
// В apps/web/lib/identity.ts или где используется Argon2id:
const mode = getArgon2ModeForContext('login'); // MODERATE вместо SENSITIVE
```

---

## 📈 Ожидаемые результаты

| Метрика | До | После |
|---------|-------|---------|
| Время загрузки главной страницы | 2-5 сек | < 500 мс |
| Время инициализации при входе в чат | 2-5 сек | < 1.5 сек (в фоне) |
| Main Thread блокировка | ДА ❌ | НЕТ ✓ |
| Визуальные лаги | ДА ❌ | НЕТ ✓ |
| Отзывчивость UI | Плохая | Отличная |

---

## ⚠️ Важные замечания

### О безопасности
- **Web Workers отделены от Main Thread**: код в Worker'е не имеет доступа к DOM, но МОЖЕТ иметь доступ к IndexedDB и другим API
- **Приватные ключи в Worker'е**: ключи генерируются в Worker'е, но отправляются в Main Thread через postMessage (которая может быть перехвачена в подконтрольной среде)
- **Рекомендация**: использовать HTTPS и Content Security Policy

### О производительности
- **Worker initialization**: создание Worker'а занимает ~100 мс (один раз)
- **postMessage overhead**: отправка сообщений быстрая (~1 мс)
- **Argon2id MODERATE**: безопасен для большинства сценариев, все еще защищает от GPU-атак

### О браузерной совместимости
- Web Workers поддерживаются всеми современными браузерами
- Fallback: если Worker недоступен, используется Main Thread (медленнее, но работает)

---

## 🔍 Отладка

### Просмотр логов Worker'а
```typescript
// В Worker'е используется self.console
console.log('[CryptoWorker] Message'); // Видно в DevTools

// В Main Thread используется обычный console
console.log('[Main] Message');
```

### Профилирование
```typescript
// Перед криптографической операцией
const start = performance.now();
await manager.generateIdentity();
const duration = performance.now() - start;
console.log(`Generation took ${duration.toFixed(0)}ms`);
```

---

## 📚 Дальнейшие оптимизации

1. **Shared Memory**: использовать SharedArrayBuffer для более быстрой передачи больших данных
2. **Worker Pool**: создавать несколько Worker'ов для параллельных операций
3. **Caching**: кэшировать сгенерированные ключи и параметры
4. **Preloading**: предварительно загружать WASM модули через Link rel="preload"
