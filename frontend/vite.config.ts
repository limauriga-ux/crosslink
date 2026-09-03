import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: '../cmd/gui/assets',
    emptyOutDir: true
  },
  server: {
    port: 5173,
    strictPort: false
  }
})
