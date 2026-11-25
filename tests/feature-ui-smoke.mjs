import { chromium } from '../web/node_modules/playwright-core/index.mjs'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const base = process.env.RDNS_UI_BASE
const browser = await chromium.launch({ executablePath: process.env.RDNS_CHROME, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } })
const errors = []
page.on('pageerror', error => errors.push(error.message))
const nav = name => page.locator('aside nav button').filter({ hasText: name }).click()
const save = async () => {
  const saved = page.waitForResponse(response => response.url() === base + '/api/v1/features' && response.request().method() === 'PUT')
  await page.getByRole('button', { name: '保存并立即应用' }).click()
  assert((await saved).ok())
  await page.getByText('操作已完成', { exact: true }).waitFor()
}
try {
  await page.addInitScript(() => {
    const NativeSocket = window.WebSocket
    window.NativeSocket = NativeSocket
    window.WebSocket = class extends NativeSocket {
      constructor(...args) {
        super(...args)
        window.consoleSocket = this
        this.addEventListener('message', event => {
          if (JSON.parse(event.data).type === 'ready') window.socketSessions = (window.socketSessions || 0) + 1
        })
      }
    }
  })
  await page.goto(base + '/admin')
  await page.getByLabel('用户名', { exact: true }).fill('admin')
  await page.getByLabel('密码', { exact: true }).fill('x')
  await page.getByRole('button', { name: /登录控制台/ }).click()
  await page.getByRole('heading', { name: '概览', exact: true }).waitFor()
  await page.getByRole('button',{name:'查询日志',exact:true}).click()
  await page.getByRole('heading',{name:'查询活动'}).waitFor()
  await nav('高级设置')
  await page.getByRole('button',{name:'客户端',exact:true}).click()
  await page.getByRole('radio', { name: /白名单模式/ }).check()
  const cidrs = page.getByLabel('允许的网段', { exact: false })
  await cidrs.fill('127.0.0.0/8\n::1/128')
  // A concurrent saved-state notification must preserve this unsaved form.
  await page.evaluate(async () => {
    const headers = { Authorization: `Bearer ${sessionStorage.getItem('rdns-token')}`, 'Content-Type': 'application/json' }
    const { settings } = await fetch('/api/v1/features', { headers }).then(r => r.json())
    await fetch('/api/v1/features', { method: 'PUT', headers, body: JSON.stringify(settings) })
  })
  await page.waitForTimeout(200)
  assert.equal(await cidrs.inputValue(), '127.0.0.0/8\n::1/128')
  await page.waitForFunction(() => window.socketSessions === 1)
  await page.evaluate(() => window.consoleSocket.close())
  await page.waitForFunction(() => window.socketSessions >= 2)
  assert.equal(await cidrs.inputValue(), '127.0.0.0/8\n::1/128')
  await save()
  await page.screenshot({ path: join(tmpdir(), 'rdns-ui-clients-desktop.png'), fullPage: true })
  await nav('高级设置')
  assert.equal(await page.locator('aside nav button').count(),5)
  const sections = page.getByRole('navigation',{name:'高级设置栏目'})
  await sections.getByRole('button',{name:'监听服务'}).click()
  await page.getByRole('heading',{name:'协议监听'}).waitFor()
  await sections.getByRole('button',{name:'证书'}).click()
  await page.getByLabel('证书链路径').waitFor()
  await sections.getByRole('button',{name:'解析上游'}).click()
  const proxyInput = page.getByLabel('全局代理地址')
  assert.equal(await proxyInput.getAttribute('type'),'text')
  await page.getByLabel('代理订阅源',{exact:true}).waitFor()
  const savedProxy = await proxyInput.inputValue()
  await proxyInput.fill('http://127.0.0.1:1')
  await page.getByRole('button',{name:'测试代理',exact:true}).click()
  await page.getByText(/代理测试失败/).waitFor()
  await proxyInput.fill(savedProxy)
  await page.getByRole('button', { name: '添加上游组', exact: true }).click()
  const lastGroup = page.locator('.upstream-group').last()
  await lastGroup.getByRole('button',{name:'添加地址'}).click()
  assert.equal(await lastGroup.locator('.upstream-source').count(), 2)
  await lastGroup.locator('.upstream-source').last().getByRole('button',{name:'移除地址'}).click()
  assert.equal(await lastGroup.locator('.upstream-source').count(), 1)
  await lastGroup.getByLabel('组名称', { exact: true }).fill('ui-test')
  await lastGroup.getByLabel('DoH 地址', { exact: true }).fill(`${process.env.RDNS_UI_UPSTREAM}/one`)
  await lastGroup.getByLabel('引导 IP（可选）', { exact: true }).fill('127.0.0.1')
  await page.getByLabel('解析模式').selectOption('parallel')
  await page.getByLabel('递归优先等待（毫秒）').fill('75')
  await save()
  await page.screenshot({ path: join(tmpdir(), 'rdns-ui-upstreams-desktop.png'), fullPage: true })
  const state = await page.evaluate(async () => fetch('/api/v1/features', { headers: { Authorization: `Bearer ${sessionStorage.getItem('rdns-token')}` } }).then(r => r.json()))
  assert.equal(state.settings.resolution.mode, 'parallel')
  assert.equal(state.settings.resolution.priority_ms, 75)
  assert(state.settings.groups.some(group => group.name === 'ui-test'))
  await nav('缓存预热')
  const parallelism = page.getByLabel('后台查询并发数',{exact:false})
  const savedParallelism = await parallelism.inputValue()
  const nextParallelism = savedParallelism === '8' ? '4' : '8'
  for (const limit of [nextParallelism,savedParallelism]) {
    await parallelism.fill(limit)
    const update = page.waitForResponse(r=>r.url()===base+'/api/v1/cache' && r.request().method()==='PUT')
    await page.getByRole('button',{name:'保存缓存设置'}).click()
    assert.equal((await (await update).json()).settings.background_concurrency,Number(limit))
    await page.getByText('操作已完成',{exact:true}).waitFor()
  }
  assert.equal(await page.getByLabel('地区热点域名预热').isChecked(),false)
  assert.equal(await page.getByLabel('顶级域名 NS 缓存').isChecked(),false)
  await page.getByLabel('搜索国家或地区').fill('JP')
  await page.getByLabel('日本 · JP').check()
  await page.getByLabel('Cloudflare API Token').fill('browser-test-token')
  await page.getByRole('button',{name:'保存缓存预加载配置'}).click()
  await page.getByPlaceholder('已配置，留空保留').waitFor()
  assert.equal(await page.getByLabel('Cloudflare API Token').inputValue(),'')
  await page.getByLabel('清除已保存的 Token').check()
  await page.getByRole('button',{name:'保存缓存预加载配置'}).click()
  await page.getByPlaceholder('输入 API Token').waitFor()
  await nav('解析规则')
  await page.getByRole('button',{name:'订阅源',exact:true}).click()
  const bounds = await page.locator('.subscription-editor .panel, .subscription-editor ~ section.panel').evaluateAll(nodes=>nodes.map(node=>{
    const {left,right}=node.getBoundingClientRect()
    return [left,right]
  }))
  assert(bounds.length>=4 && bounds.every(([l,r])=>Math.abs(l-bounds[0][0])<1 && Math.abs(r-bounds[0][1])<1),'subscription panels must align')
  await page.getByRole('heading',{name:'AdGuard 广告过滤'}).waitFor()
  const upstream = process.env.RDNS_UI_UPSTREAM
  const geo = page.locator('section').filter({has:page.getByRole('heading',{name:'GeoIP 来源地区'})})
  const geoUrl = i => geo.getByLabel('下载地址',{exact:true}).nth(i)
  await geoUrl(0).fill(upstream+'/v4')
  await geoUrl(1).fill(upstream+'/invalid')
  await save()
  // Keep another source dirty while refreshing all four independently.
  const cycle = async (name, path, status) => {
    const button = page.getByRole('button',{name,exact:true})
    await Promise.all([
      page.waitForResponse(r=>r.url()===base+'/api/v1/'+path && r.request().method()==='POST')
        .then(r=>assert.equal(r.status(),status)),
      button.click()
    ])
    await button.waitFor()
    assert(await button.isEnabled())
  }
  await page.getByLabel('AdGuard 更新周期（小时）').fill('48')
  await cycle('下载并更新 IPv6','geoip/refresh',502)
  await cycle('下载并更新 IPv4','geoip/refresh',200)
  await cycle('下载并更新 IPv4','geoip/refresh',200)
  await cycle('立即更新 GFWList','gfwlist/refresh',200)
  await cycle('立即更新 AdGuard','adguard/refresh',502)
  assert.equal(await page.getByLabel('AdGuard 更新周期（小时）').inputValue(),'48')
  await geoUrl(1).fill(upstream+'/v6')
  await page.getByLabel('AdAway 地址').fill(upstream+'/ads')
  await save()
  await cycle('下载并更新 IPv6','geoip/refresh',200)
  await cycle('立即更新 AdGuard','adguard/refresh',200)
  await page.getByRole('checkbox', { name: '向用户开放 GFWList 分流' }).check()
  await save()
  assert(await page.getByText(/两组均失败时返回错误/).isVisible())
  await page.getByRole('heading',{name:'GeoIP 来源地区'}).waitFor()
  await page.getByLabel('来源 IP', { exact: true }).fill('8.8.8.8')
  await page.getByRole('button', { name: '查询 IP', exact: true }).click()
  await page.locator('.lookup-result').waitFor()
  assert((await page.locator('.lookup-result').textContent()).includes('广东省'))
  await page.getByLabel('来源 IP',{exact:true}).fill('1.1.1.1')
  await page.getByRole('button',{name:'查询 IP',exact:true}).click()
  await page.getByText('1.1.1.1 的归属地',{exact:true}).waitFor()
  await page.getByText('该 IP 未包含在客户端白名单网段中',{exact:true}).waitFor()
  await page.setViewportSize({ width: 390, height: 844 })
  await page.screenshot({ path: join(tmpdir(), 'rdns-ui-geoip-mobile.png'), fullPage: true })
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'mobile viewport overflows horizontally')
  await nav('高级设置')
  await page.getByRole('button',{name:'客户端',exact:true}).click()
  await page.screenshot({ path: join(tmpdir(), 'rdns-ui-clients-mobile.png'), fullPage: true })
  // Every stats() call queries SQLite and allocates a new sample ID.
  // Additional authenticated subscribers must receive the same two consecutive samples.
  const samples = await page.evaluate(async () => {
    const token = sessionStorage.getItem('rdns-token')
    const firstPair = socket => new Promise((resolve, reject) => {
      const ids = []
      const timeout = setTimeout(() => { socket.removeEventListener('message', receive); reject(new Error('cache samples timed out')) }, 12000)
      function receive(event) {
        const message = JSON.parse(event.data)
        if (message.type !== 'cache') return
        ids.push(message.stats.sample_id)
        if (ids.length === 2) {
          clearTimeout(timeout)
          socket.removeEventListener('message', receive)
          resolve(ids)
        }
      }
      socket.addEventListener('message', receive)
    })
    const one = await firstPair(window.consoleSocket)
    const extra = await Promise.all(Array.from({length: 9}, () => new Promise((resolve, reject) => {
      const socket = new window.NativeSocket(window.consoleSocket.url)
      socket.onerror = reject
      socket.onopen = () => socket.send(JSON.stringify({type:'auth', token}))
      socket.onmessage = event => { if (JSON.parse(event.data).type === 'ready') resolve(socket) }
    })))
    try {
      const ten = await Promise.all([window.consoleSocket, ...extra].map(firstPair))
      return {one, ten}
    } finally { extra.forEach(socket => socket.close()) }
  })
  assert.equal(samples.one[1] - samples.one[0], 1)
  for (const pair of samples.ten) assert.deepEqual(pair, samples.ten[0])
  assert.equal(samples.ten[0][1] - samples.ten[0][0], 1)
  await page.evaluate(async () => {
    const response = await fetch('/api/v1/logout', { method: 'POST', headers: { Authorization: `Bearer ${sessionStorage.getItem('rdns-token')}` } })
    if (!response.ok) throw new Error('session revocation failed')
    if (window.consoleSocket.readyState === WebSocket.OPEN) {
      window.consoleSocket.send(JSON.stringify({type: 'cache.update', request_id: 42, settings: {memory_mib: 1, ns_max_ttl: 1, answer_max_ttl: 1, negative_max_ttl: 1}}))
    }
  })
  await page.getByRole('button', { name: /登录控制台/ }).waitFor({ timeout: 10000 })
  assert.equal(await page.evaluate(() => sessionStorage.getItem('rdns-token')), null)
  assert.deepEqual(errors, [])
  console.log('PASS: browser login, HTTP configuration saves, WebSocket reconnection and session revocation, unsaved-edit preservation, upstream groups, GFWList, GeoIP lookup and desktop/mobile layouts')
} finally {
  await browser.close()
}
