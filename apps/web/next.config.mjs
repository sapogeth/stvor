import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

// Diagnostic logging
const __filename = fileURLToPath(import.meta.url);
const appDir = path.dirname(__filename);
const workspaceRoot = path.join(appDir, '../..');
console.log('[next-config] __dirname =', appDir);
console.log('[next-config] App directory:', path.join(appDir, 'app'));
console.log('[next-config] Workspace root (outputFileTracingRoot) =', workspaceRoot);
console.log('[next-config] Expected page.tsx at:', path.join(appDir, 'app', 'page.tsx'));

const nextConfig = {
  // Transpile monorepo packages
  transpilePackages: ['@ilyazh/crypto'],

  // Using default webpack bundler (Next 14.x)
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.resolve.alias = {
        ...config.resolve.alias,
        '@openforge-sh/liboqs': path.resolve(appDir, './stubs/liboqs-browser-stub.js'),
      };
    }

    config.module = {
      ...config.module,
      exprContextCritical: false,
    };

    const require = createRequire(import.meta.url);
    config.resolve.fallback = {
      ...config.resolve.fallback,
      crypto: false,
      stream: false,
      buffer: require.resolve('buffer/'),
    };

    return config;
  },
};

export default nextConfig;
