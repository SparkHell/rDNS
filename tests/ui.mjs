import { createRequire } from 'node:module'
import dgram from 'node:dgram'

const requireWeb = createRequire(new URL('../web/package.json', import.meta.url))
const { chromium } = requireWeb('playwright-core')
const [base, token, screenshot] = process.argv.slice(2)
const browser = await chromium.launch({ executablePath: '/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 })
  await page.goto(base + '/admin')
  await page.evaluate(value => sessionStorage.setItem('rdns-token', value), token)
  await page.reload()
  await page.getByText('从根开始，可信解析。').waitFor()
  await page.screenshot({ path: screenshot, fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await page.screenshot({ path: screenshot.replace(/\.png$/, '-mobile.png'), fullPage: true })
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)
  if (overflow) throw new Error('mobile dashboard has horizontal overflow')
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.getByRole('button', { name: '解析规则' }).click()
  await page.getByText('internal.example').waitFor()
  await page.getByRole('button', { name: '高级设置', exact: true }).click()
    await page.getByRole('button', { name: '监听服务' }).click()
  await page.getByText('协议监听').waitFor()
  await page.screenshot({ path: screenshot.replace(/\.png$/, '-listeners.png'), fullPage: true })
  const wsResult = await page.evaluate(token => new Promise((resolve, reject) => {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const socket = new WebSocket(`${protocol}//${location.host}/api/v1/ws`)
    let original = null
    let phase = 0
    const timer = setTimeout(() => { socket.close(); reject(new Error('listener WebSocket timed out')) }, 5000)
    socket.onopen = () => socket.send(JSON.stringify({ type: 'auth', token }))
    socket.onmessage = event => {
      const message = JSON.parse(event.data)
      if (message.type === 'listeners' && !original) {
        original = message.settings
        const disabled = { ...original, dns_udp: { ...original.dns_udp, enabled: false } }
        socket.send(JSON.stringify({ type: 'listeners.update', request_id: 1, settings: disabled }))
      }
      if (message.type === 'result') {
        if (!message.ok) { clearTimeout(timer); socket.close(); reject(new Error(message.error)); return }
        if (phase++ === 0) socket.send(JSON.stringify({ type: 'listeners.update', request_id: 2, settings: original }))
        else { clearTimeout(timer); socket.close(); resolve(true) }
      }
    }
    socket.onerror = () => { clearTimeout(timer); reject(new Error('listener WebSocket failed')) }
  }), token)
  if (!wsResult) throw new Error('listener update was not acknowledged')
  await page.getByRole('button', { name: '缓存预热' }).click()
  await page.getByText('递归缓存').waitFor()
  await page.getByLabel('热点内存预算（MiB）').waitFor()
  await page.screenshot({ path: screenshot.replace(/\.png$/, '-cache.png'), fullPage: true })
  await page.getByLabel('热点内存预算（MiB）').fill('32')
  await page.waitForTimeout(3500)
  if (await page.getByLabel('热点内存预算（MiB）').inputValue() !== '32') throw new Error('live cache status overwrote an unsaved edit')
  await page.getByRole('button', { name: '保存缓存设置' }).click()
  await page.waitForTimeout(300)
  const cacheResponse = await fetch(`${base}/api/v1/cache`, { headers: { Authorization: `Bearer ${token}` } })
  const savedCache = await cacheResponse.json()
  if (savedCache.settings.memory_mib !== 32) throw new Error(`HTTP cache update failed: ${JSON.stringify(savedCache)}`)
  const occupied = dgram.createSocket('udp4')
  await new Promise(resolve => occupied.bind(0, '127.0.0.1', resolve))
  try {
    await page.getByRole('button', { name: '高级设置', exact: true }).click()
    await page.getByRole('button', { name: '监听服务' }).click()
    await page.getByLabel('DNS · UDP 监听地址').fill(`127.0.0.1:${occupied.address().port}`)
    await page.getByRole('button', { name: '保存并应用' }).click()
    await page.getByText(/dns_udp.*端口不可用/).waitFor({ timeout: 5000 })
  } finally { occupied.close() }
  await page.getByRole('button', { name: '证书' }).click()
  await page.getByLabel('证书链路径').waitFor()
  await page.getByLabel('私钥路径').waitFor()
  await page.getByRole('button', { name: '保存路径并应用' }).waitFor()
  await page.getByRole('button', { name: '重载当前路径' }).waitFor()
  await page.screenshot({ path: screenshot.replace(/\.png$/, '-certificates.png'), fullPage: true })
  console.log('PASS: authenticated dashboard, WebSocket listener update, certificate path settings')
} finally {
  await browser.close()
}
