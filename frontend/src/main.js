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
    { path: '/', component: ListView },
    { path: '/vuln/:id', component: DetailView },
    { path: '/templates', component: TemplatesView },
    { path: '/settings', component: SettingsView },
  ],
})

createApp(App).use(router).mount('#app')
