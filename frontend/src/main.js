// main.js —— 应用入口：装配路由，把 App 挂到页面上。
//
// 路由刻意用 history 模式，不是 hash。URL 干净是一方面，更重要的是筛选条件
// （搜索词、来源页签、页码）能直接躺在地址栏上，刷新和分享都还原得回来。

import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import ListView from './ListView.vue'
import DetailView from './DetailView.vue'
import TemplatesView from './TemplatesView.vue'
import SettingsView from './SettingsView.vue'

const router = createRouter({
    history: createWebHistory(),
    routes: [
        { path: '/', component: ListView }, // 漏洞列表（首页，总览面板嵌在其中）
        { path: '/vuln/:id', component: DetailView }, // 漏洞详情
        { path: '/templates', component: TemplatesView }, // nuclei 模板库
        { path: '/settings', component: SettingsView }, // 设置
    ],
})

createApp(App).use(router).mount('#app')