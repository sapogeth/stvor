# 🚀 Stv0r (Ilyazh Messenger) - Deployment Guide

## Quantum-Resistant E2EE Messenger Deployment

**Security Model:**
- **Browser** = Crypto endpoint (all encryption/decryption client-side)
- **Relay** = Encrypted bulletin board (zero-knowledge, stores ciphertext only)
- **Database** = Encrypted blobs + public identities (NO private keys)

---

## 📋 Prerequisites

1. **Package Manager:** pnpm v9.0.0+ (`corepack enable`)
2. **Node.js:** v20.0.0+
3. **Docker:** v24.0+ (for local deployment)
4. **Supabase Account:** https://supabase.com (for PostgreSQL)
5. **Clerk Account:** https://clerk.com (for authentication)
6. **Vercel Account:** https://vercel.com (for frontend hosting)
7. **Railway/Render Account:** For relay deployment

---

## 🔐 Security Checklist (BEFORE DEPLOYMENT)

- [ ] JWT_SECRET is ≥32 chars (generate with `openssl rand -base64 48`)
- [ ] DATABASE_URL uses Supabase production credentials
- [ ] ALLOWED_ORIGINS does NOT contain `*` (whitelist only)
- [ ] STORAGE_TYPE=postgres (NOT memory or filesystem)
- [ ] ALLOW_DEV_AUTOCREATE=0 (disabled in production)
- [ ] All NEXT_PUBLIC_DEBUG_* flags are 0
- [ ] .env files are in .gitignore (never commit secrets)
- [ ] CORS is properly configured (tested with curl)

---

## 🛠️ Local Development Setup

### 1. Install Dependencies

```bash
# Install pnpm if not already installed
corepack enable
corepack prepare pnpm@9.0.0 --activate

# Install all dependencies
pnpm install

# Build all packages
pnpm turbo run build
```

### 2. Set Up Environment Variables

#### Frontend (`apps/web/.env.local`)

```bash
# Copy template
cp apps/web/.env.example apps/web/.env.local

# Edit and fill:
NEXT_PUBLIC_RELAY_URL=http://localhost:3001
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_YOUR_KEY
CLERK_SECRET_KEY=sk_test_YOUR_KEY
NEXT_PUBLIC_SUPABASE_URL=https://uppanfnstjeybiseolmo.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=YOUR_ANON_KEY
NEXT_PUBLIC_DEBUG_CRYPTO=1  # Enable for local debugging
```

#### Relay (`apps/relay/.env`)

```bash
# Copy template
cp apps/relay/.env.example apps/relay/.env

# Generate JWT secret
JWT_SECRET=$(openssl rand -base64 48)
echo "JWT_SECRET=$JWT_SECRET" >> apps/relay/.env

# Edit and fill:
DATABASE_URL=postgresql://postgres:PASSWORD@db.uppanfnstjeybiseolmo.supabase.co:5432/postgres
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3002
STORAGE_TYPE=postgres
NODE_ENV=development
ALLOW_DEV_AUTOCREATE=1  # Enable for local dev
```

### 3. Run Development Servers

```bash
# Terminal 1: Run relay
cd apps/relay
pnpm dev

# Terminal 2: Run web frontend
cd apps/web
pnpm dev

# Access at http://localhost:3002 (Next.js)
# Relay at http://localhost:3001
```

---

## 🐳 PATH 1: Docker Compose Deployment (Local/VPS)

### With Local PostgreSQL

```bash
# Generate secrets
export JWT_SECRET=$(openssl rand -base64 48)
export POSTGRES_PASSWORD=$(openssl rand -base64 32)

# Start services
docker compose up -d

# Check health
curl http://localhost:3001/healthz
# Expected: {"status":"ok","storage":"postgres","version":"0.8.0"}

# View logs
docker compose logs -f relay

# Stop services
docker compose down
```

### With Supabase PostgreSQL

Edit `docker-compose.yml` and comment out the `postgres` service, then:

```bash
# Set Supabase credentials
export JWT_SECRET=$(openssl rand -base64 48)
export DATABASE_URL="postgresql://postgres:narutp222@db.uppanfnstjeybiseolmo.supabase.co:5432/postgres"

# Update relay environment in docker-compose.yml
# DATABASE_URL: ${DATABASE_URL}

# Start relay only
docker compose up -d relay

# Test
curl http://localhost:3001/healthz
```

---

## ☁️ PATH 2: Cloud Deployment (Supabase + Railway + Vercel)

### Step 1: Deploy Relay to Railway

1. **Go to Railway:** https://railway.app/new
2. **Deploy from GitHub:**
   - Connect your GitHub account
   - Select `ilyazh-messenger` repository
   - Railway auto-detects `Dockerfile`
3. **Set Environment Variables in Railway Dashboard:**

```bash
JWT_SECRET=<paste from: openssl rand -base64 48>
DATABASE_URL=postgresql://postgres:narutp222@db.uppanfnstjeybiseolmo.supabase.co:5432/postgres
ALLOWED_ORIGINS=http://localhost:3000,https://stv0r.vercel.app,https://stv0r-*.vercel.app
STORAGE_TYPE=postgres
NODE_ENV=production
ALLOW_DEV_AUTOCREATE=0
HOST=0.0.0.0
LOG_LEVEL=info
```

4. **Deploy** and copy your Railway URL (e.g., `https://stv0r-relay-production.up.railway.app`)

### Step 2: Deploy Frontend to Vercel

1. **Go to Vercel:** https://vercel.com/new
2. **Import GitHub Repository:** `ilyazh-messenger`
3. **Configure Project:**
   - **Framework:** Next.js (auto-detected)
   - **Root Directory:** `apps/web`
   - **Build Command:** `pnpm turbo run build --filter=@ilyazh/web`
   - **Install Command:** `pnpm install --frozen-lockfile`
   - **Output Directory:** `.next` (default)
4. **Set Environment Variables in Vercel Dashboard:**

```bash
NEXT_PUBLIC_RELAY_URL=https://YOUR-RAILWAY-URL.up.railway.app
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_YOUR_KEY
CLERK_SECRET_KEY=sk_live_YOUR_KEY
NEXT_PUBLIC_SUPABASE_URL=https://uppanfnstjeybiseolmo.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
NEXT_PUBLIC_DEBUG_CRYPTO=0
NEXT_PUBLIC_DEBUG_AUTH=0
NEXT_PUBLIC_DEBUG_SYNC=0
NEXT_PUBLIC_DEBUG_IDENTITY=0
```

5. **Deploy** and copy your Vercel URL (e.g., `https://stv0r.vercel.app`)

### Step 3: Update CORS in Relay

Go back to Railway and update `ALLOWED_ORIGINS`:

```bash
ALLOWED_ORIGINS=https://stv0r.vercel.app,https://stv0r-*.vercel.app,http://localhost:3000
```

Railway will auto-redeploy.

---

## 🧪 Testing Production Deployment

### Test Relay Health

```bash
# Replace with your Railway/Render URL
RELAY_URL="https://YOUR-RELAY-URL.up.railway.app"

# Health check
curl "$RELAY_URL/healthz"
# Expected: {"status":"ok","storage":"postgres","version":"0.8.0"}

# Readiness check
curl "$RELAY_URL/ready"
# Expected: {"ready":true,"storage":"postgres","version":"0.8.0"}

# Metrics
curl "$RELAY_URL/metrics"

# Directory lookup (should 404 until first user registers)
curl "$RELAY_URL/directory/alice"
# Expected: {"error":"User not found"}
```

### Test CORS

```bash
# Should succeed (whitelisted origin)
curl -H "Origin: https://stv0r.vercel.app" "$RELAY_URL/healthz"

# Should fail (not in whitelist)
curl -H "Origin: https://attacker.com" "$RELAY_URL/healthz"
# Expected: CORS error
```

### Test E2E Crypto Flow

1. Open your Vercel URL in browser
2. Register two test users (e.g., `alice` and `bob`)
3. Send message from Alice to Bob
4. Verify Bob receives and decrypts message
5. Check safety numbers match
6. **CRITICAL:** Verify relay logs show ONLY encrypted blobs (NO plaintext)

```bash
# Check relay logs (Railway dashboard)
# You should see base64 encrypted blobs, NOT plaintext messages
# If you see plaintext → SECURITY BREACH
```

---

## 🔍 Troubleshooting

### Problem: "JWT_SECRET must be ≥32 chars"

**Fix:** Generate strong secret:
```bash
openssl rand -base64 48
```

### Problem: CORS error in browser

**Fix:** Update `ALLOWED_ORIGINS` in relay to include your Vercel domain

### Problem: Database connection fails

**Fix:** Verify Supabase connection string:
```bash
# Get from: https://supabase.com/dashboard/project/uppanfnstjeybiseolmo/settings/database
# Format: postgresql://postgres:PASSWORD@db.uppanfnstjeybiseolmo.supabase.co:5432/postgres
```

### Problem: Messages not syncing

**Fix:** Check relay logs for errors, verify `STORAGE_TYPE=postgres`

---

## 📊 Monitoring

### Railway/Render Logs

```bash
# Railway: View in dashboard
# Render: View in dashboard

# Look for:
[SECURITY] events (auth failures, rate limits)
[Session] operations (session creation/updates)
[Message] operations (message storage)
[CORS] events (allowed/blocked origins)
```

### Health Checks

Railway/Render automatically monitor `/healthz` endpoint.

---

## 🔐 Security Guarantees

**✅ Verified:**
- AAD with session-id: PRESENT (packages/crypto/src/wire.ts)
- Dual signatures (Ed25519 + ML-DSA-65): PRESENT (packages/crypto/src/handshake.ts)
- Message padding (PKCS#7, 256B): PRESENT
- CORS: SAFE (no wildcard `*`)
- Zero-knowledge schema: VERIFIED (only encrypted blobs + public keys)
- Device re-enrollment: INTACT
- Secret logging: NONE

**❌ DO NOT:**
- Remove AAD or session-id binding
- Disable dual signatures
- Change message padding or CBOR format
- Set CORS to `*`
- Log JWT_SECRET, DATABASE_URL, or private keys
- Move encryption from client to relay
- Enable dev auto-creation in production

---

## 📝 Git Workflow

```bash
# DO NOT commit secrets
git status  # Verify no .env files are staged

# Commit deployment configs (templates only)
git add .
git commit -m "Add production deployment configs"

# Push to remote
git remote add origin https://github.com/YOUR_USERNAME/stv0r.git
git push -u origin main
```

---

## 🎯 Success Criteria

Your deployment is successful when:

1. ✅ Relay `/healthz` returns `{"status":"ok","storage":"postgres"}`
2. ✅ Frontend loads without console errors
3. ✅ Alice can register and send message to Bob
4. ✅ Bob receives and decrypts Alice's message
5. ✅ Safety numbers match between Alice and Bob
6. ✅ Relay logs show ONLY encrypted blobs (NOT plaintext)
7. ✅ CORS blocks unauthorized origins

**🎉 Congratulations! Your quantum-resistant E2EE messenger is live.**

---

## 📚 Additional Resources

- **Supabase Dashboard:** https://supabase.com/dashboard/project/uppanfnstjeybiseolmo
- **Railway Dashboard:** https://railway.app
- **Vercel Dashboard:** https://vercel.com/dashboard
- **Clerk Dashboard:** https://dashboard.clerk.com

---

## 🆘 Support

If you encounter issues:
1. Check relay logs for errors
2. Verify all environment variables are set correctly
3. Test CORS with curl
4. Verify database connectivity
5. Check browser console for frontend errors
