import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: { '/api': { target: process.env.RASP_API_URL || 'http://127.0.0.1:8480' } },
  },
  build: { target: 'es2022', sourcemap: false, chunkSizeWarningLimit: 400 },
})
