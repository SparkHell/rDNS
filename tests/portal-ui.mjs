import { createRequire } from 'node:module'
import assert from 'node:assert/strict'

const { chromium } = createRequire(new URL('../web/package.json', import.meta.url))('playwright-core')
const [origin, admin] = process.argv.slice(2)
const token = process.env.RDNS_TEST_ADMIN_TOKEN
const browser = await chromium.launch({
  executablePath: process.env.RDNS_CHROME || '/bin/chromium',
  args: ['--no-sandbox'],
})
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 390, height: 844 } })
  const page = await context.newPage()
  await page.goto(origin + '/portal')
  await page.getByLabel('用户名').fill('alice')
  await page.getByLabel('密码').fill('test-password')
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await page.getByRole('heading', { name: 'alice 的 DNS' }).waitFor()
  await page.getByText('portal.test', { exact: true }).first().waitFor()
  const url = page.getByLabel('解析器 URL')
  const old = await url.inputValue()
  page.once('dialog', (dialog) => dialog.accept())
  await page.getByRole('button', { name: '更换地址' }).click()
  await page.waitForFunction((previous) => document.querySelector('input[readonly]')?.value !== previous, old)
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
  const cookie = (await context.cookies()).find((c) => c.name === '__Host-rdns-portal')
  assert.ok(cookie?.httpOnly && cookie.secure)
  await page.getByRole('button', { name: '退出登录' }).click()
  await page.getByRole('heading', { name: '登录用户门户' }).waitFor()
  await page.goto(admin)
  await page.evaluate((t) => sessionStorage.setItem('rdns-token', t), token)
  await page.reload()
  await page.setViewportSize({ width: 1280, height: 900 })
  await page.getByRole('button', { name: '用户门户' }).click()
  await page.getByRole('heading', { name: '门户用户' }).waitFor()
  await page.getByLabel('注册策略').selectOption('approval')
  await page.getByRole('button', { name: '保存并应用' }).click()
  await page.getByRole('status').filter({hasText:'已应用'}).waitFor()
  await page.getByLabel('用户筛选', { exact: true }).selectOption({ label: 'alice · #1' })
  await page.getByText('portal.test', { exact: true }).first().waitFor()
  const rejected = await page.evaluate(
    (secret) =>
      new Promise((resolve) => {
        const ws = new WebSocket('ws://' + location.host + '/api/v1/ws')
        ws.onopen = () => ws.send(JSON.stringify({ type: 'auth', token: secret }))
        ws.onclose = (e) => resolve(e.code)
        ws.onmessage = (e) => {
          if (JSON.parse(e.data).type === 'ready') {
            ws.close()
            resolve(0)
          }
        }
      }),
    cookie.value,
  )
  assert.equal(rejected, 1008)
} finally {
  await browser.close()
}
