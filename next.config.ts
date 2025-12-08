import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'help.sendmarc.com',
        pathname: '/hubfs/**',
      },
    ],
  },
};

export default nextConfig;
