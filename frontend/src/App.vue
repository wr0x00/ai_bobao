<template>
  <div class="wrap">
    <header>
      <h1 @click="$router.push('/')">AI 漏洞播报</h1>
      <span class="sub">24h 监控 · AI 筛选 · 自动生成 PoC</span>
      <nav>
        <a href="#" :class="{ on: $route.path === '/' }" @click.prevent="$router.push('/')">漏洞</a>
        <a href="#" :class="{ on: $route.path === '/templates' }" @click.prevent="$router.push('/templates')">nuclei 模板库</a>
        <a href="#" :class="{ on: $route.path === '/settings' }" @click.prevent="$router.push('/settings')">设置</a>
      </nav>
    </header>
    <router-view />
  </div>
</template>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0f1115; color: #e6e6e6; font-family: system-ui, 'Microsoft YaHei', sans-serif; }
.wrap { max-width: 860px; margin: 0 auto; padding: 24px 16px 60px; }
header { margin-bottom: 24px; cursor: default; }
header h1 { font-size: 22px; cursor: pointer; display: inline-block; }
header .sub { margin-left: 12px; color: #8b93a1; font-size: 13px; }
header nav { float: right; display: flex; gap: 14px; font-size: 13px; }
header nav a { color: #8b93a1; }
header nav a.on { color: #e6e6e6; }
a { color: #5aa7ff; text-decoration: none; }
</style>
