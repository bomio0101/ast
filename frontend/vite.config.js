// frontend/vite.config.js
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue"; // 确保 vue 插件已安装并引入

export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: {
      // 代理 /upload 请求
      "/upload": {
        target: "http://localhost:5000", // 您的后端 Flask 服务器地址
        changeOrigin: true, // 对于虚拟主机站点是必需的
      },
      // 代理 /results 请求
      "/results": {
        target: "http://localhost:5000", // 您的后端 Flask 服务器地址
        changeOrigin: true,
      },
      // 如果您有其他API端点，也可以在这里添加
    },
  },
});
