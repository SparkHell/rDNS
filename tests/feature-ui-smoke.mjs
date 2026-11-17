import { chromium } from '../web/node_modules/playwright-core/index.mjs'
import assert from 'node:assert/strict'

const base = process.env.RDNS_UI_BASE
const browser = await chromium.launch({ executablePath: '/opt/google/chrome/chrome', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } })
const errors = []
page.on('pageerror', error => errors.push(error.message))
const nav = name => page.locator('aside nav button').filter({ hasText: name }).click()
const save = async () => {
  await page.getByRole('button', { name: '保存并立即应用' }).click()
  await page.getByText('操作已完成', { exact: true }).waitFor()
}
try {
  await page.goto(base)
  await page.getByLabel('用户名', { exact: true }).fill('admin')
  await page.getByLabel('密码', { exact: true }).fill('x')
  await page.getByRole('button', { name: /登录控制台/ }).click()
  await page.getByRole('heading', { name: '概览', exact: true }).waitFor()
  await nav('客户端')
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
  await save()
  await page.screenshot({ path: '/tmp/rdns-ui-clients-desktop.png', fullPage: true })
  await nav('解析上游')
  await page.getByRole('button', { name: '添加上游组', exact: true }).click()
  const lastGroup = page.locator('.upstream-group').last()
  await lastGroup.getByLabel('组名称', { exact: true }).fill('ui-test')
  await lastGroup.getByLabel('DoH 地址', { exact: true }).fill(`${process.env.RDNS_UI_UPSTREAM}/one`)
  await lastGroup.getByLabel('引导 IP（可选）', { exact: true }).fill('127.0.0.1')
  await page.getByLabel('解析模式').selectOption('parallel')
  await page.getByLabel('递归优先等待（毫秒）').fill('75')
  await save()
  await page.screenshot({ path: '/tmp/rdns-ui-upstreams-desktop.png', fullPage: true })
  const state = await page.evaluate(async () => fetch('/api/v1/features', { headers: { Authorization: `Bearer ${sessionStorage.getItem('rdns-token')}` } }).then(r => r.json()))
  assert.equal(state.settings.resolution.mode, 'parallel')
  assert.equal(state.settings.resolution.priority_ms, 75)
  assert(state.settings.groups.some(group => group.name === 'ui-test'))
  await nav('GFWList')
  await page.getByRole('checkbox', { name: '启用 GFWList 分流' }).check()
  await save()
  assert(await page.getByText(/两组均失败时返回错误/).isVisible())
  await nav('来源地区')
  await page.getByLabel('来源 IP', { exact: true }).fill('8.8.8.8')
  await page.getByRole('button', { name: '查询 IP', exact: true }).click()
  await page.locator('.lookup-result').waitFor()
  assert((await page.locator('.lookup-result').textContent()).includes('广东省'))
  await page.setViewportSize({ width: 390, height: 844 })
  await page.screenshot({ path: '/tmp/rdns-ui-geoip-mobile.png', fullPage: true })
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'mobile viewport overflows horizontally')
  await nav('客户端')
  await page.screenshot({ path: '/tmp/rdns-ui-clients-mobile.png', fullPage: true })
  assert.deepEqual(errors, [])
  console.log('PASS: browser login, WebSocket configuration saves, unsaved-edit preservation, upstream groups, GFWList, GeoIP lookup and desktop/mobile layouts')
} finally {
  await browser.close()
}
