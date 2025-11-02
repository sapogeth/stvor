#!/bin/bash
cd /Users/ilaszajsenbaev/ilyazh-messenger/apps/web
export ALLOW_DEV_AUTOCREATE=1
export NEXT_PUBLIC_RELAY_URL=http://localhost:3001
export PORT=3003
pnpm dev
