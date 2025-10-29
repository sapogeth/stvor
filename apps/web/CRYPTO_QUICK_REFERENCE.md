# Crypto Quick Reference Card

**🚀 Most common operations for developers**

---

## Import the Safe Crypto Interface

```typescript
import { getCryptoOrThrow } from '@/lib/runtime/crypto-safe';
```

---

## Generate a UUID

```typescript
const { randomUUID } = getCryptoOrThrow();
const id = randomUUID();
// Example: "550e8400-e29b-41d4-a716-446655440000"
```

---

## Check if Crypto is Available

```typescript
import { isCryptoAvailable } from '@/lib/runtime/crypto-safe';

if (isCryptoAvailable()) {
  // Show encryption features
} else {
  // Show "HTTPS required" message
}
```

---

## Initialize Crypto (Root Component)

```typescript
'use client';
import { initCryptoOnce } from '@/lib/crypto/init';

export default function RootLayout({ children }) {
  useEffect(() => {
    initCryptoOnce()
      .then(() => console.log('Crypto ready'))
      .catch(err => console.error('Crypto init failed:', err));
  }, []);

  return children;
}
```

---

## Add Error Boundary

```typescript
import { CryptoErrorBoundary } from '@/components/CryptoErrorBoundary';

export default function App() {
  return (
    <CryptoErrorBoundary>
      {/* Your app components */}
    </CryptoErrorBoundary>
  );
}
```

---

## Check Initialization State

```typescript
import { getCryptoInitState, isCryptoReady } from '@/lib/crypto/init';

// Simple boolean check
if (isCryptoReady()) {
  // Crypto is initialized and ready
}

// Detailed state
const state = getCryptoInitState();
// Returns: 'idle' | 'initializing' | 'ready' | 'failed'
```

---

## Get Diagnostics

```typescript
import { getCryptoStatus } from '@/lib/runtime/crypto-safe';

const status = getCryptoStatus();
console.log('Secure context:', status.isSecure);
console.log('Has SubtleCrypto:', status.hasSubtle);
console.log('Has randomUUID:', status.hasRandomUUID);
console.log('Runtime context:', status.context);
```

---

## Handle Errors Gracefully

```typescript
import { tryRandomUUID } from '@/lib/runtime/crypto-safe';

const id = tryRandomUUID();
if (id) {
  // Success
} else {
  // Handle error (crypto unavailable)
}
```

---

## Visit Diagnostics Page

**URL**: `/debug/crypto`

Shows:
- ✓ Browser support status
- ✓ Feature availability
- ✓ Live tests (IndexedDB, WASM, etc.)
- ✓ Recommendations

---

## Common Errors & Fixes

| Error | Fix |
|-------|-----|
| "Secure context required" | Use HTTPS or localhost |
| "IndexedDB not available" | Disable private browsing |
| "Server-side rendering" | Move to client-side (useEffect) |
| "crypto.subtle not available" | Update browser |

---

## Do's and Don'ts

### ✅ DO
- Use `getCryptoOrThrow()` for all crypto operations
- Call `initCryptoOnce()` from root client component
- Check `isCryptoAvailable()` before showing crypto UI
- Use the diagnostics page to debug issues

### ❌ DON'T
- Don't use `self.crypto.randomUUID()` directly
- Don't call crypto APIs during SSR
- Don't use `Math.random()` for security
- Don't skip error boundaries

---

## File Locations

| What | Where |
|------|-------|
| Safe crypto interface | `apps/web/lib/runtime/crypto-safe.ts` |
| Environment detection | `apps/web/lib/runtime/crypto-env.ts` |
| Initialization | `apps/web/lib/crypto/init.ts` |
| Error boundary | `apps/web/components/CryptoErrorBoundary.tsx` |
| Diagnostics page | `apps/web/app/debug/crypto/page.tsx` |
| Documentation | `apps/web/CRYPTO_INIT.md` |

---

## Testing

```bash
# Unit tests
pnpm test apps/web/lib/runtime/__tests__/crypto-env.test.ts

# E2E tests
pnpm test:e2e apps/web/__tests__/e2e/crypto-init.spec.ts

# Visit diagnostics
open http://localhost:3000/debug/crypto
```

---

**Need more details?** See [CRYPTO_INIT.md](CRYPTO_INIT.md)
