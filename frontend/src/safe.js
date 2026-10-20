// safe.js —— 前端取值的最后一道关
//
// 后端已经把外部数据洗过一遍（safe_refs 只留 http/https、require_vid 只留字母数字），
// 但前端是数据落地前的最后一道关：URL 会直接进 href，路径会直接进 router.push。
// 上游哪天改了一行代码，这里还能再挡一次，所以这两个判断单独收在一个文件里。

// 只放行这两种协议。javascript:、data:、vbscript:、file: 一律当脏数据处理。
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:'])

/**
 * 把一个外部地址变成能安全放进 href 的值。
 * 协议不在白名单里就返回空串，调用方据此渲染成纯文本，而不是一个能点的链接。
 *
 * @param {unknown} value 待检查的地址
 * @returns {string} 合法返回规范化后的地址，非法返回空串
 */
export function safeUrl(value) {
  const raw = String(value ?? '').trim()
  if (!raw) return ''
  let parsed
  try {
    // 用 URL 解析而不是自己拆字符串：浏览器会把首尾空白、换行、tab 都吃掉，
    // "java\nscript:alert(1)" 这种拼法在 URL 解析器眼里就是 javascript:。
    parsed = new URL(raw)
  } catch {
    return ''
  }
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) return ''
  return parsed.href
}

/**
 * 把 URL 上带回来的站内路径校验一遍。
 *
 * 只接受以单个斜杠开头的站内绝对路径。挡掉的是两种浏览器会当成外站的写法：
 * "//evil.com" 和 "/\evil.com"（WHATWG 规范里 special scheme 下反斜杠等同正斜杠）。
 * 最后再比一次 origin，双保险。
 *
 * @param {unknown} value 待检查的路径
 * @returns {string} 合法返回规范化后的路径，非法返回空串
 */
export function safePath(value) {
  const raw = String(value ?? '').trim()
  if (!raw.startsWith('/')) return ''
  if (raw.startsWith('//') || raw.startsWith('/\\')) return ''
  let parsed
  try {
    parsed = new URL(raw, window.location.origin)
  } catch {
    return ''
  }
  if (parsed.origin !== window.location.origin) return ''
  return parsed.pathname + parsed.search + parsed.hash
}
