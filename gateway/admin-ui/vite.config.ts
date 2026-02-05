import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/admin/',
  build: {
    outDir: '../public/admin',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/admin/api': {
        target: 'http://localhost:3100',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/admin\/api/, '/admin'),
      },
    },
  },
})
