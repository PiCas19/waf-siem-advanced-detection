import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react({
      jsxRuntime: 'automatic' // Fix: Non serve più importare React
    })
  ],
  server: {
    port: 3000,
    middleware: [
      (req, res, next) => {
  res.setHeader('Content-Security-Policy', "img-src 'self' data: https://tile.openstreetmap.org https://*.tile.openstreetmap.org https://a.tile.openstreetmap.org https://b.tile.openstreetmap.org https://c.tile.openstreetmap.org https://*.openstreetmap.org https://api.dicebear.com https://api.qrserver.com;");
        next();
      }
    ],
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:8081',
        changeOrigin: true,
      }
    }
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 1000, // Suppress warnings for chunks up to 1MB
    rollupOptions: {
      output: {
        manualChunks: {
          // Vendor libraries
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-charts': ['recharts'],
          'vendor-ui': ['lucide-react', 'tailwindcss'],
          // Large component pages
          'page-stats': ['./src/components/stats/StatsPage.tsx'],
          'page-logs': ['./src/components/logs/LogViewer.tsx'],
          'page-blocklist': ['./src/components/blocklist/BlocklistPage.tsx'],
        }
      }
    }
  }
})