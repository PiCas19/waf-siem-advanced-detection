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
        res.setHeader('Content-Security-Policy', "img-src 'self' data: https://tile.openstreetmap.org https://*.tile.openstreetmap.org");
        next();
      }
    ],
    proxy: {
      '/api': {
        target: 'http://localhost:8081',
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
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom']
        }
      }
    }
  }
})