/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  serverExternalPackages: ['pino', 'pino-pretty'],
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://localhost:4100/api/:path*',
      },
    ];
  },
};

module.exports = nextConfig;
