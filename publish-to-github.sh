#!/bin/bash

echo "🚀 Publishing Stv0r to GitHub"
echo "================================"
echo ""

# Prompt for GitHub username
read -p "Enter your GitHub username: " USERNAME

if [ -z "$USERNAME" ]; then
  echo "❌ Error: Username cannot be empty"
  exit 1
fi

echo ""
echo "📝 Repository will be created at:"
echo "   https://github.com/$USERNAME/Stv0r"
echo ""
read -p "Press Enter to continue (or Ctrl+C to cancel)..."

# Check if remote already exists
if git remote | grep -q origin; then
  echo "⚠️  Remote 'origin' already exists. Removing..."
  git remote remove origin
fi

# Add GitHub remote
echo "🔗 Adding GitHub remote..."
git remote add origin "https://github.com/$USERNAME/Stv0r.git"

# Rename branch to main if needed
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
  echo "📝 Renaming branch to 'main'..."
  git branch -M main
fi

# Show instructions
echo ""
echo "✅ Git repository configured!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 NEXT STEPS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Create the repository on GitHub:"
echo "   👉 https://github.com/new"
echo ""
echo "   Repository name: Stv0r"
echo "   Description: 🔐 Quantum-resistant end-to-end encrypted messenger"
echo "   Visibility: Public ✅"
echo "   DO NOT add README, .gitignore, or license"
echo ""
echo "2. After creating the repo, push your code:"
echo ""
echo "   git push -u origin main"
echo ""
echo "3. Update README for public:"
echo ""
echo "   mv README.md README_OLD.md"
echo "   mv README_PUBLIC.md README.md"
echo "   git add README.md README_OLD.md"
echo "   git commit -m \"Update README for public release\""
echo "   git push"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📖 Full instructions: GITHUB_SETUP.md"
echo ""
