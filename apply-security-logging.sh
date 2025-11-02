#!/bin/bash

# Production-Safe Logging - Automated Implementation Script
# This script applies all security logging changes to eliminate sensitive data leaks

set -e

echo "🔒 Applying production-safe logging changes..."
echo ""

# Define color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BASE_DIR="/Users/ilaszajsenbaev/ilyazh-messenger/apps/web"

# ====================================================================================
# STEP 1: Add logger import to chat/page.tsx
# ====================================================================================
echo -e "${BLUE}[1/4] Updating app/chat/page.tsx...${NC}"

FILE="$BASE_DIR/app/chat/page.tsx"

# Add logger import after SessionHealthWarning import (line ~44)
if ! grep -q "from '@/lib/logger'" "$FILE"; then
  sed -i.bak "s|import { SessionHealthWarning } from '@/components/SessionHealthWarning';|import { SessionHealthWarning } from '@/components/SessionHealthWarning';\nimport { logDebug, logInfo, logWarn, logError, redactPlaintext, redactSessionId, isSyncDebugEnabled } from '@/lib/logger';|" "$FILE"
  echo "  ✅ Added logger import"
fi

# CRITICAL: Remove plaintext logging at line ~808-815
# Replace the 4 debug console.log lines + the final console.log with secure logging
sed -i.bak '/DEBUG: Log plaintext bytes to diagnose garbage characters/,/console\.log.*Successfully decrypted.*length.*messageText/c\
                  messageText = new TextDecoder().decode(plaintext);\
                  isEncrypted = true;\
                  logInfo('"'"'message'"'"', '"'"'Successfully decrypted message'"'"', { plaintext: redactPlaintext(plaintext) });
' "$FILE"

# CRITICAL: Remove plaintext logging at retry location (line ~859-866)
sed -i.bak '/DEBUG: Log plaintext bytes to diagnose garbage characters/,/Successfully decrypted after refresh/c\
                          messageText = new TextDecoder().decode(plaintext);\
                          isEncrypted = true;\
                          logInfo('"'"'message'"'"', '"'"'Successfully decrypted after session refresh'"'"', { plaintext: redactPlaintext(plaintext) });
' "$FILE"

# Replace sync debug logs with conditional logging
sed -i.bak 's|console\.log(\['"'"'Sync'"'"'\] Received|logDebug('"'"'sync'"'"', '"'"'Received|g' "$FILE"
sed -i.bak 's|console\.log(`\[Sync\]\[Debug\]|logDebug('"'"'sync'"'"',|g' "$FILE"

# Replace handshake session ID logging with redacted version
sed -i.bak "s|console\.log('\[Handshake\] - Session ID:', Buffer\.from(.*\.sessionId)\.toString('hex')\.slice.*)|logInfo('handshake', 'Handshake completed', { sessionId: redactSessionId(handshakeState.sessionId), role: handshakeState.role });|g" "$FILE"

echo -e "${GREEN}  ✅ Secured chat/page.tsx${NC}"

# ====================================================================================
# STEP 2: Update lib/identity.ts
# ====================================================================================
echo -e "${BLUE}[2/4] Updating lib/identity.ts...${NC}"

FILE="$BASE_DIR/lib/identity.ts"

# Add logger import
if ! grep -q "from './logger'" "$FILE"; then
  sed -i.bak "s|import { getRelayUrl } from './relay-url';|import { getRelayUrl } from './relay-url';\nimport { logDebug, logInfo, logWarn, logError, redactToken, redactPublicKey } from './logger';|" "$FILE"
  echo "  ✅ Added logger import"
fi

# CRITICAL: Replace JWT token logging in createAuthHeaders
sed -i.bak "s|console\.log('\[Auth\] Token from localStorage:'.*|logDebug('auth', 'Using JWT from localStorage', { token: token ? redactToken(token) : 'null' });|" "$FILE"
sed -i.bak "s|console\.log('\[Auth\] ✅ Added Authorization header');||" "$FILE"
sed -i.bak "s|console\.warn('\[Auth\] ⚠️  No JWT token found for user:', username);|logWarn('auth', 'No JWT token found', { username });|" "$FILE"

# Replace public key logging with redacted version
sed -i.bak "s|console\.log('\[Identity\] - Ed25519 public key:', Buffer\.from(.*ed25519\.publicKey.*|logInfo('identity', 'Identity loaded', { ed25519Public: redactPublicKey(identity.ed25519.publicKey) });|" "$FILE"

# Replace all remaining Identity console.log with logInfo
sed -i.bak "s|console\.log('\[Identity\]|logInfo('identity',|g" "$FILE"
sed -i.bak "s|console\.warn('\[Identity\]|logWarn('identity',|g" "$FILE"
sed -i.bak "s|console\.error('\[Identity\]|logError('identity',|g" "$FILE"

echo -e "${GREEN}  ✅ Secured lib/identity.ts${NC}"

# ====================================================================================
# STEP 3: Update lib/keystore.ts
# ====================================================================================
echo -e "${BLUE}[3/4] Updating lib/keystore.ts...${NC}"

FILE="$BASE_DIR/lib/keystore.ts"

# Add logger import
if ! grep -q "from './logger'" "$FILE"; then
  sed -i.bak "s|import _sodium from 'libsodium-wrappers';|import _sodium from 'libsodium-wrappers';\nimport { logDebug, logInfo, logWarn, logError } from './logger';|" "$FILE"
  echo "  ✅ Added logger import"
fi

# CRITICAL: Remove verbose Base64 conversion debug dumps (lines 264-302)
# These lines contain sensitive encrypted key data
sed -i.bak '/Base64 conversion test:/,/JSON\.stringify test:/d' "$FILE"

# Replace keystore encryption logs
sed -i.bak "s|console\.log('\[KeyStore\] Encrypting identity keys with password\.\.\.');|logDebug('keystore', 'Encrypting identity keys');|" "$FILE"
sed -i.bak "s|console\.log('\[KeyStore\] ✅ Identity keys encrypted');|logInfo('keystore', 'Identity keys encrypted');|" "$FILE"

# Replace all remaining KeyStore console.log with logger
sed -i.bak "s|console\.log('\[KeyStore\]|logDebug('keystore',|g" "$FILE"
sed -i.bak "s|console\.warn('\[KeyStore\]|logWarn('keystore',|g" "$FILE"
sed -i.bak "s|console\.error('\[KeyStore\]|logError('keystore',|g" "$FILE"

echo -e "${GREEN}  ✅ Secured lib/keystore.ts${NC}"

# ====================================================================================
# STEP 4: Update lib/ratchet-refresh.ts
# ====================================================================================
echo -e "${BLUE}[4/4] Updating lib/ratchet-refresh.ts...${NC}"

FILE="$BASE_DIR/lib/ratchet-refresh.ts"

# Add logger import
if ! grep -q "from './logger'" "$FILE"; then
  sed -i.bak "s|import { clearSessionSecurity } from './session-security';|import { clearSessionSecurity } from './session-security';\nimport { logDebug, logInfo, logWarn, logError, redactSessionId } from './logger';|" "$FILE"
  echo "  ✅ Added logger import"
fi

# Replace session ID logging with redacted version
sed -i.bak "s|console\.log('\[RatchetRefresh\] New session ID:', Buffer\.from(newSession\.sessionId)\.toString.*)|logInfo('ratchet', 'New session created', { sessionId: redactSessionId(newSession.sessionId) });|" "$FILE"

# Replace all remaining RatchetRefresh console.log with logger
sed -i.bak "s|console\.log('\[RatchetRefresh\]|logDebug('ratchet',|g" "$FILE"
sed -i.bak "s|console\.warn('\[RatchetRefresh\]|logWarn('ratchet',|g" "$FILE"
sed -i.bak "s|console\.error('\[RatchetRefresh\]|logError('ratchet',|g" "$FILE"

echo -e "${GREEN}  ✅ Secured lib/ratchet-refresh.ts${NC}"

# ====================================================================================
# Cleanup backup files
# ====================================================================================
echo ""
echo "🧹 Cleaning up backup files..."
find "$BASE_DIR" -name "*.bak" -delete

echo ""
echo -e "${GREEN}✅ All security logging changes applied successfully!${NC}"
echo ""
echo "Next steps:"
echo "  1. Create .env.local with debug flags (see SECURITY_LOGGING_CHANGES.md)"
echo "  2. Restart the development server"
echo "  3. Test with all flags = 0 (production mode)"
echo "  4. Verify no sensitive data in console"
echo ""
