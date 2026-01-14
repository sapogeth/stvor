/** @type {import('next').NextConfig} */
const nextConfig = {
  // Базовая строгая проверка React
  reactStrictMode: true,

  // Транспиляция монорепо-пакета с криптографией
  transpilePackages: ['@ilyazh/crypto'],

  // CRITICAL: Rewrites для проксирования запросов к Relay серверу
  // В браузере все запросы идут через /api/relay/*, которые проксируются на Railway
  async rewrites() {
    const relayUrl = process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';
    
    console.log('[Next.js] Relay rewrites configured:', relayUrl);
    
    return [
      {
        source: '/api/relay/:path*',
        destination: `${relayUrl}/:path*`,
      },
    ];
  },

  webpack: (config, { isServer }) => {
    // 1. Включаем поддержку WebAssembly (нужно для PQ-криптографии)
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true,
      layers: true,
    };

    // 2. Корректный вывод wasm для сервера/клиента
    if (isServer) {
      config.output.webassemblyModuleFilename = './../static/wasm/[modulehash].wasm';
    } else {
      config.output.webassemblyModuleFilename = 'static/wasm/[modulehash].wasm';
    }

    // 3. Fallback'и для браузерной сборки
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
      	path: false,
        crypto: false,
      };
    }

    // 4. CRITICAL: Prevent liboqs from bundling in browser
    // liboqs is WASM-based and should only load dynamically
    if (!isServer) {
      config.externals = config.externals || [];
      // Mark liboqs as external for client bundle - it will be loaded via dynamic import
      config.externals.push({
        '@openforge-sh/liboqs': 'commonjs @openforge-sh/liboqs',
      });
    }

    // 5. Suppress liboqs "Critical dependency" warnings
    // These are from dynamic WASM loading and are expected
    config.ignoreWarnings = [
      ...(config.ignoreWarnings || []),
      {
        module: /node_modules\/@openforge-sh\/liboqs/,
        message: /Critical dependency: the request of a dependency is an expression/,
      },
    ];

    return config;
  },
};

export default nextConfig;
