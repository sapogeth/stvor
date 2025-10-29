# 🚀 GitHub Repository Setup Guide

Follow these steps to publish Stv0r to GitHub:

---

## Step 1: Create GitHub Repository

1. Go to https://github.com/new
2. Fill in the details:
   - **Repository name**: `Stv0r`
   - **Description**: `🔐 Quantum-resistant end-to-end encrypted messenger with post-quantum cryptography (ML-KEM-768, ML-DSA-65)`
   - **Visibility**: Public ✅
   - **DO NOT** initialize with README, .gitignore, or license (we already have these)

3. Click **"Create repository"**

---

## Step 2: Push Your Code

After creating the repository, GitHub will show you instructions. Run these commands:

```bash
# Make sure you're in the project directory
cd /Users/ilaszajsenbaev/ilyazh-messenger

# Add GitHub as remote (replace YOUR_USERNAME with your actual GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/Stv0r.git

# Push the code
git branch -M main
git push -u origin main
```

**Example** (if your username is `ilaszajsenbaev`):
```bash
git remote add origin https://github.com/ilaszajsenbaev/Stv0r.git
git branch -M main
git push -u origin main
```

---

## Step 3: Configure Repository Settings

### 3.1 Set Repository Description
1. Go to your repository on GitHub
2. Click the ⚙️ gear icon next to "About"
3. Add:
   - **Description**: `🔐 Quantum-resistant end-to-end encrypted messenger with post-quantum cryptography`
   - **Website**: (leave empty for now, or add deployment URL later)
   - **Topics**: `encryption`, `cryptography`, `post-quantum`, `messenger`, `e2e`, `security`, `typescript`, `nextjs`, `quantum-resistant`

### 3.2 Add README Badge
The repository already has a nice README_PUBLIC.md. To use it:

```bash
# Rename the public README to be the main one
mv README.md README_OLD.md
mv README_PUBLIC.md README.md

# Commit and push
git add README.md README_OLD.md
git commit -m "Update README for public release"
git push
```

### 3.3 Enable GitHub Pages (Optional)
To host documentation:
1. Go to Settings → Pages
2. Source: Deploy from a branch
3. Branch: main / docs (if you have a docs folder)

---

## Step 4: Create Public Access Link

Your repository will be accessible at:
```
https://github.com/YOUR_USERNAME/Stv0r
```

Anyone can:
- ✅ View the code
- ✅ Clone/fork the repository
- ✅ Create issues
- ✅ Submit pull requests

---

## Step 5: Deploy for Public Access

### Option A: Quick Deploy (Vercel - Recommended)

**For Web Client**:
1. Go to https://vercel.com
2. Click "New Project"
3. Import from GitHub: `YOUR_USERNAME/Stv0r`
4. Framework: Next.js (auto-detected)
5. Root Directory: `apps/web`
6. Environment Variables:
   ```
   NEXT_PUBLIC_RELAY_URL=https://your-relay-url.com
   ```
7. Click "Deploy"

You'll get a URL like: `https://stv0r.vercel.app`

**For Relay Server**:
1. Use Railway.app or Fly.io
2. Deploy `apps/relay` directory
3. Set environment variable:
   ```
   JWT_SECRET=your-random-secret-key
   NODE_ENV=production
   PORT=3001
   ```
4. Get your relay URL and update Vercel's `NEXT_PUBLIC_RELAY_URL`

### Option B: Self-Hosted

```bash
# On your server
git clone https://github.com/YOUR_USERNAME/Stv0r.git
cd Stv0r

# Install and build
pnpm install
pnpm build

# Start relay server
cd apps/relay
JWT_SECRET="your-secret" PORT=3001 node dist/index.js &

# Start web server
cd apps/web
npm start
```

---

## Step 6: Share Registration Link

Once deployed, users can register by visiting:

```
https://your-domain.com
```

**Example Flow**:
1. User visits your site
2. Enters username
3. Automatically registered with JWT token
4. Can start chatting immediately!

**No email required, no phone number, just a username! 🎉**

---

## Step 7: Add License

Create a LICENSE file:

```bash
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2025 Stv0r Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

git add LICENSE
git commit -m "Add MIT License"
git push
```

---

## Quick Commands Summary

```bash
# 1. Create repo on GitHub (manual step)

# 2. Push code
git remote add origin https://github.com/YOUR_USERNAME/Stv0r.git
git branch -M main
git push -u origin main

# 3. Update README
mv README.md README_OLD.md
mv README_PUBLIC.md README.md
git add README.md README_OLD.md
git commit -m "Update README for public release"
git push

# 4. Add license
cat > LICENSE << 'EOF'
MIT License
Copyright (c) 2025 Stv0r Team
...
EOF
git add LICENSE
git commit -m "Add MIT License"
git push
```

---

## 🎉 Done!

Your repository is now public and accessible at:
```
https://github.com/YOUR_USERNAME/Stv0r
```

Share this link with anyone who wants to:
- Use the messenger
- Contribute code
- Report security issues
- Fork and customize

---

## 📱 Sharing the App

Once deployed, share your registration link:

**Marketing Message**:
> 🔐 **Try Stv0r** - The quantum-resistant encrypted messenger!
>
> ✅ Post-quantum cryptography (ML-KEM-768, ML-DSA-65)
> ✅ End-to-end encryption
> ✅ No phone number required
> ✅ Zero-knowledge server
>
> Register now: https://your-domain.com
>
> GitHub: https://github.com/YOUR_USERNAME/Stv0r

---

## ⚠️ Important Security Notes

Before making it public:

1. **Set JWT_SECRET** in production:
   ```bash
   # Generate a secure secret
   openssl rand -base64 32
   ```

2. **Enable HTTPS**: WebCrypto requires HTTPS in production

3. **Review security docs**: Read [SECURITY_COMPLETED.md](SECURITY_COMPLETED.md)

4. **Test thoroughly**: Try registering and chatting with 2+ users

---

## 🆘 Troubleshooting

### "Authentication required" errors
- Users need to clear browser storage and re-register
- See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)

### Can't push to GitHub
```bash
# If you see authentication error
gh auth login  # Or use SSH keys
```

### Deployment fails
- Check Node.js version (18+ required)
- Verify environment variables are set
- Check build logs for errors

---

**Questions?** Open an issue on GitHub!
