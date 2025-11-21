# Deployment Checklist - Registration Flow Fix

Use this checklist to deploy all four fixes and verify the complete registration flow works.

## Code Deployment

- [ ] **All commits pushed to main**
  ```bash
  git log --oneline | head -10
  # Should show:
  # - wrap identity fields in nested object
  # - migrate profile storage to Supabase
  # - add production domains to relay CORS
  ```

- [ ] **Vercel deployment complete**
  - [ ] Check https://vercel.com/your-project/deployments
  - [ ] Latest deployment shows green checkmark
  - [ ] Deployment includes Supabase client code

- [ ] **Railway deployment complete**
  - [ ] Check https://railway.app/project/ilyazhrelay-production
  - [ ] Latest deployment shows green status
  - [ ] Deployment includes CORS fixes

## Supabase Configuration

- [ ] **Profiles table created**
  - [ ] Go to https://supabase.com/dashboard
  - [ ] Select your project
  - [ ] Go to SQL editor
  - [ ] Run SQL from PROFILE_STORAGE_SETUP.md
  - [ ] Verify table exists

- [ ] **Anon key extracted**
  - [ ] Settings → API
  - [ ] Copy "URL" → `NEXT_PUBLIC_SUPABASE_URL`
  - [ ] Copy "anon public" → `NEXT_PUBLIC_SUPABASE_ANON_KEY`

## Vercel Configuration

- [ ] **Supabase environment variables set**
  - [ ] NEXT_PUBLIC_SUPABASE_URL
  - [ ] NEXT_PUBLIC_SUPABASE_ANON_KEY
  - [ ] Both available to Production environment

## Railway Configuration

- [ ] **ALLOWED_ORIGINS set**
  ```
  https://stvor.xyz,https://www.stvor.xyz,https://clerk.stvor.xyz,http://localhost:3000,http://localhost:3002,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3002
  ```

## End-to-End Testing

- [ ] New user registration completes
- [ ] Profile persists in Supabase
- [ ] No CORS errors in logs
- [ ] No "identity verification failed" errors
- [ ] No cascade failures

See REGISTRATION_FIX_SUMMARY.md for detailed testing procedure.
