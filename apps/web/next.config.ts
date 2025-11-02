import type { NextConfig } from 'next';
import path from 'path';

// Diagnostic logging
const appDir = __dirname;
const workspaceRoot = path.join(__dirname, '../..');
console.log('[next-config] __dirname =', appDir);
console.log('[next-config] App directory:', path.join(appDir, 'app'));
console.log('[next-config] Workspace root (outputFileTracingRoot) =', workspaceRoot);
console.log('[next-config] Expected page.tsx at:', path.join(appDir, 'app', 'page.tsx'));

const nextConfig: NextConfig = {
  // CRITICAL FIX: Explicitly set workspace root to prevent Next.js from detecting
  // the wrong root due to lockfiles in parent directories
  outputFileTracingRoot: workspaceRoot,

  // Transpile monorepo packages
  transpilePackages: ['@ilyazh/crypto'],

  webpack: (config, { isServer }) => {
    // Browser-side: stub out the heavy PQ library to prevent webpack errors
    // This allows the root page to compile while keeping E2E crypto intact
    if (!isServer) {
      config.resolve.alias = {
        ...config.resolve.alias,
        '@openforge-sh/liboqs': path.resolve(__dirname, './stubs/liboqs-browser-stub.js'),
      };
    }

    // Silence "Critical dependency: the request of a dependency is an expression" warnings
    // These come from liboqs dynamic requires which we're stubbing out on the client anyway
    config.module = {
      ...config.module,
      exprContextCritical: false,
    };

    config.resolve.fallback = {
      ...config.resolve.fallback,
      crypto: false,
      stream: false,
      buffer: require.resolve('buffer/'),
    };

    return config;
  },
  // SECURITY: Content Security Policy is handled in middleware.ts
  // This allows dynamic CSP based on environment and Clerk configuration
  // See apps/web/middleware.ts for the actual CSP implementation
};

export default nextConfig;
