import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    // changeOrigin 把 Host 头改成后端地址（127.0.0.1:8100）。
    // 后端有 Host 白名单挡 DNS 重绑定，转发时必须让 Host 落在白名单里。
    proxy: { '/api': { target: 'http://127.0.0.1:8100', changeOrigin: true } },
  },
})
