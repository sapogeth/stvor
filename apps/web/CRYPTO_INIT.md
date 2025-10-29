# Crypto Initialization & Browser Support

This document describes the cryptographic initialization system and browser compatibility for the Ilyazh messenger.

## Overview

The crypto initialization system provides:

- **Runtime detection** of WebCrypto API availability
- **Polyfills** for missing browser features (e.g., `crypto.randomUUID`)
- **SSR/CSR guards** to prevent server-side crypto operations
- **WASM readiness** coordination for libsodium and liboqs
- **IndexedDB warming** to prevent cold-start race conditions
- **Diagnostics UI** for troubleshooting browser compatibility

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Application Layer                          │
│  - Components, hooks, pages                                  │
└───────────────────┬─────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────┐
│              Crypto Safe Interface                           │
│  apps/web/lib/runtime/crypto-safe.ts                         │
│  - getCryptoOrThrow() → Validated crypto interface          │
│  - isCryptoAvailable() → Feature detection                  │
└───────────────────┬─────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────┐
│            Environment Detection                             │
│  apps/web/lib/runtime/crypto-env.ts                          │
│  - detectCryptoEnv() → Runtime environment                  │
│  - uuidv4_gRV() → RFC4122 v4 polyfill                       │
│  - randomUUID() → Native or polyfilled                      │
└───────────────────┬─────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────┐
│          Centralized Initialization                          │
│  apps/web/lib/crypto/init.ts                                 │
│  - initCryptoOnce() → Race-free init                        │
│  - Coordinates: WebCrypto, libsodium, liboqs, IndexedDB     │
└─────────────────────────────────────────────────────────────┘
```

## Key Files

### Runtime Detection & Polyfills

**[apps/web/lib/runtime/crypto-env.ts](apps/web/lib/runtime/crypto-env.ts)**

- `detectCryptoEnv()` - Detects available crypto features
- `uuidv4_gRV()` - RFC4122 v4 UUID generator using `crypto.getRandomValues`
- `randomUUID()` - Uses native or polyfilled UUID generation
- `validateCryptoEnvironment()` - Throws descriptive errors if crypto unavailable

**[apps/web/lib/runtime/crypto-safe.ts](apps/web/lib/runtime/crypto-safe.ts)**

- `getCryptoOrThrow()` - Single import point for all crypto operations
- `isCryptoAvailable()` - Non-throwing availability check
- `getCryptoStatus()` - Detailed diagnostics

### Initialization

**[apps/web/lib/crypto/init.ts](apps/web/lib/crypto/init.ts)**

- `initCryptoOnce()` - Idempotent initialization (safe to call multiple times)
- Coordinates:
  1. WebCrypto API validation
  2. libsodium WASM loading
  3. liboqs WASM loading (when available)
  4. IndexedDB keystore warming
- `getCryptoInitState()` - Current state: `idle | initializing | ready | failed`
- `isCryptoReady()` - Boolean check

### Error Handling

**[apps/web/components/CryptoErrorBoundary.tsx](apps/web/components/CryptoErrorBoundary.tsx)**

- React Error Boundary for crypto initialization failures
- Categorizes errors and provides actionable solutions
- Links to diagnostics page

### Diagnostics

**[/debug/crypto](apps/web/app/debug/crypto/page.tsx)** - Live diagnostics page

Shows:
- Runtime context (SSR/CSR/Worker)
- WebCrypto API availability
- IndexedDB functionality
- WASM library readiness
- Browser-specific recommendations

## Usage

### Basic Usage

```typescript
import { getCryptoOrThrow } from '@/lib/runtime/crypto-safe';

// In a client component or hook
useEffect(() => {
  const { randomUUID } = getCryptoOrThrow();
  const id = randomUUID();
  console.log('Generated ID:', id);
}, []);
```

### Initialization

```typescript
import { initCryptoOnce } from '@/lib/crypto/init';

// In root layout or provider (client-side only!)
'use client';

export default function RootLayout({ children }) {
  useEffect(() => {
    initCryptoOnce().catch(err => {
      console.error('Crypto init failed:', err);
    });
  }, []);

  return children;
}
```

### Error Boundary

```typescript
import { CryptoErrorBoundary } from '@/components/CryptoErrorBoundary';

export default function App() {
  return (
    <CryptoErrorBoundary>
      <YourApp />
    </CryptoErrorBoundary>
  );
}
```

### Feature Detection

```typescript
import { isCryptoAvailable } from '@/lib/runtime/crypto-safe';

if (isCryptoAvailable()) {
  // Show encryption UI
} else {
  // Show "HTTPS required" message
}
```

## Browser Support

### Minimum Requirements

| Feature | Requirement | Chrome | Firefox | Safari | Edge |
|---------|------------|--------|---------|--------|------|
| Secure Context | HTTPS or localhost | ✓ | ✓ | ✓ | ✓ |
| `crypto.subtle` | SubtleCrypto API | 37+ | 34+ | 11+ | 79+ |
| `crypto.getRandomValues` | CSPRNG | 11+ | 21+ | 6.1+ | 12+ |
| `crypto.randomUUID` | Native UUID | 92+ | 95+ | 15.4+ | 92+ |
| IndexedDB | Key storage | 24+ | 16+ | 10+ | 79+ |
| WebAssembly | libsodium/liboqs | 57+ | 52+ | 11+ | 79+ |

### Polyfills

- **`crypto.randomUUID`**: Automatically polyfilled using `crypto.getRandomValues` for Safari < 15.4 and older browsers
- **UUID format**: RFC4122 v4 compliant (xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx)
- **Security**: Never uses `Math.random()` - only cryptographically secure sources

### Known Issues

#### Safari < 15.4
- No native `crypto.randomUUID` → Polyfill automatically used
- **Fix**: Automatic (transparent to application)

#### Private Browsing Mode (All Browsers)
- IndexedDB may be disabled
- **Symptom**: "Failed to open IndexedDB" error
- **Fix**: Disable private browsing or use normal browsing mode

#### Web Workers (Safari)
- `crypto.subtle` may be unavailable in Workers
- **Fix**: Crypto operations run on main thread instead

#### HTTP (Insecure Context)
- WebCrypto APIs unavailable
- **Symptom**: "Secure context required" error
- **Fix**: Access app over HTTPS or from localhost

## Diagnostics

### Check Browser Support

Visit **[/debug/crypto](/debug/crypto)** to see:

- ✓ Secure Context (HTTPS)
- ✓ crypto.subtle present
- ✓ crypto.getRandomValues present
- ✓ crypto.randomUUID (native or polyfill)
- ✓ IndexedDB functional
- ✓ libsodium WASM loaded

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "Secure context required" | HTTP instead of HTTPS | Use HTTPS or localhost |
| "IndexedDB not available" | Private browsing mode | Disable private browsing |
| "crypto.subtle not available" | Old browser or Worker | Update browser or use main thread |
| "Server-side rendering" | Called from SSR | Move to client-side (useEffect) |

## Testing

### Unit Tests

```bash
pnpm test apps/web/lib/runtime/__tests__/crypto-env.test.ts
```

Tests:
- UUID v4 format compliance (RFC4122)
- Security properties (no Math.random)
- Environment detection accuracy
- Polyfill correctness

### E2E Tests

```bash
pnpm test:e2e apps/web/__tests__/e2e/crypto-init.spec.ts
```

Tests:
- Secure context validation
- WebCrypto availability
- Crypto initialization without errors
- IndexedDB functionality
- Cross-browser compatibility (Chrome, Firefox, Safari)

### Manual QA Checklist

- [ ] Chrome (latest): Open app, create identity, send message
- [ ] Firefox (latest): Open app, create identity, send message
- [ ] Safari (latest): Open app, create identity, send message
- [ ] Safari iOS: Open app, create identity, send message
- [ ] Private mode (any browser): Should show graceful error
- [ ] HTTP (insecure): Should show "Secure context required"
- [ ] /debug/crypto: All checks should pass (green)

## Migration Guide

### Replacing Direct `crypto.randomUUID()` Calls

**Before:**
```typescript
const id = self.crypto.randomUUID();
```

**After:**
```typescript
import { getCryptoOrThrow } from '@/lib/runtime/crypto-safe';

const { randomUUID } = getCryptoOrThrow();
const id = randomUUID();
```

### Adding Initialization to Root Component

**Before:**
```typescript
export default function RootLayout({ children }) {
  return <html>{children}</html>;
}
```

**After:**
```typescript
'use client';
import { initCryptoOnce } from '@/lib/crypto/init';

export default function RootLayout({ children }) {
  useEffect(() => {
    initCryptoOnce().catch(console.error);
  }, []);

  return <html>{children}</html>;
}
```

## Security Notes

### CSPRNG Usage

All random number generation uses **cryptographically secure** sources:

- `crypto.getRandomValues()` - WebCrypto CSPRNG
- `libsodium.randombytes_buf()` - libsodium CSPRNG
- **Never** `Math.random()` - Not suitable for cryptography

### UUID Polyfill

The UUID v4 polyfill (`uuidv4_gRV`):

1. Generates 16 random bytes using `crypto.getRandomValues()`
2. Sets version bits (4) at byte 6
3. Sets variant bits (10) at byte 8
4. Formats as xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
5. Uses lowercase hex digits

**Compliance**: RFC4122 Section 4.4

### No Node.js Polyfills in Client Bundle

The Webpack config ensures no Node.js core modules leak into the client bundle:

```javascript
// next.config.js
module.exports = {
  webpack: (config) => {
    config.resolve.fallback = {
      crypto: false,
      stream: false,
      buffer: false,
    };
    return config;
  },
};
```

Server-side code (relay) uses Node.js native crypto:

```typescript
import { webcrypto } from 'node:crypto';
const crypto = globalThis.crypto ?? webcrypto;
```

## Troubleshooting

### Issue: "TypeError: self.crypto.randomUUID is not a function"

**Cause**: Safari < 15.4 or old browser without native `randomUUID`

**Fix**: Use the polyfilled `randomUUID` from `crypto-safe.ts` (automatically used)

**Status**: ✅ Fixed by this patch

---

### Issue: "Failed to initialize encryption keys. Please refresh."

**Cause**: IndexedDB race condition during cold start

**Fix**: `initCryptoOnce()` now warms IndexedDB before first use

**Status**: ✅ Fixed by this patch

---

### Issue: "Crypto requires a secure context (https)"

**Cause**: Accessing app over HTTP instead of HTTPS

**Fix**:
1. Development: Use `https://localhost:3000` or proxy with SSL
2. Production: Ensure app is served over HTTPS

---

### Issue: Private browsing mode disables IndexedDB

**Cause**: Browsers disable storage APIs in private/incognito mode

**Fix**: Show user-friendly error with `CryptoErrorBoundary`:
- "Private mode may disable IndexedDB"
- "Switch off private browsing or use another browser"

---

## Performance

- **Initialization time**: < 5 seconds (includes WASM loading)
- **UUID generation**: < 0.1ms per UUID (1000 UUIDs in <100ms)
- **IndexedDB warm-up**: < 100ms (cached after first open)

## Future Enhancements

1. **liboqs-wasm integration**: Replace PQ crypto mocks with real liboqs
2. **Service Worker support**: Test crypto availability in SW context
3. **Shared Worker**: Consider moving crypto to SharedWorker for cross-tab efficiency
4. **Crypto key caching**: LRU cache for frequently used session keys
5. **Performance monitoring**: Track init time in production (Sentry/Analytics)

## References

- [Web Crypto API (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [RFC4122 - UUID Specification](https://www.rfc-editor.org/rfc/rfc4122.html)
- [Secure Contexts (W3C)](https://www.w3.org/TR/secure-contexts/)
- [IndexedDB API (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API)
- [libsodium Documentation](https://doc.libsodium.org/)

## Support

- **Diagnostics**: Visit [/debug/crypto](/debug/crypto)
- **Issues**: Report at [GitHub Issues](https://github.com/yourusername/ilyazh-messenger/issues)
- **Browser Compatibility**: Check [caniuse.com/cryptography](https://caniuse.com/cryptography)

---

**Last Updated**: 2025-10-29
**Next.js Version**: 15.5.6
**Target Browsers**: Chrome 92+, Firefox 95+, Safari 15.4+, Edge 92+
