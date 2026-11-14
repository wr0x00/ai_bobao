import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 前后端不分离：构建产物直接落到 backend/static，由 FastAPI 一起发出去。
// 页面和接口同源同端口，不用再单独起 vite dev server，也没有跨域问题。
export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: '../backend/static',
    emptyOutDir: true,
    assetsDir: 'assets',
  },
  server: {
    port: 5173,
    // changeOrigin 把 Host 头改成后端地址（127.0.0.1:8100）。
    // 后端有 Host 白名单挡 DNS 重绑定，转发时必须让 Host 落在白名单里。
    // 这套只用于改代码时热更新，正式跑还是走 npm run build 的单端口模式。
    proxy: { '/api': { target: 'http://127.0.0.1:8100', changeOrigin: true } },
  },
})
