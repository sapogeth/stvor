/** @type {import('next').NextConfig} */
const nextConfig = {
  // Базовая строгая проверка React
  reactStrictMode: true,

  // Транспиляция монорепо-пакета с криптографией
  transpilePackages: ['@ilyazh/crypto'],

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

    return config;
  },
};

export default nextConfig;
