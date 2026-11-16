import { createRequire } from 'node:module'

const requireWeb = createRequire(new URL('../web/package.json', import.meta.url))
const { chromium } = requireWeb('playwright-core')
const [base, token, screenshot] = process.argv.slice(2)
const browser = await chromium.launch({ executablePath: '/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 })
  await page.goto(base)
  await page.evaluate(value => sessionStorage.setItem('rdns-token', value), token)
  await page.reload()
  await page.getByText('从根开始，可信解析。').waitFor()
  await page.screenshot({ path: screenshot, fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await page.screenshot({ path: screenshot.replace(/\.png$/, '-mobile.png'), fullPage: true })
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)
  if (overflow) throw new Error('mobile dashboard has horizontal overflow')
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.getByRole('button', { name: '解析与过滤' }).click()
  await page.getByText('internal.example').waitFor()
  await page.getByRole('button', { name: '证书' }).click()
  await page.getByRole('button', { name: '重载证书' }).waitFor()
  console.log('PASS: authenticated dashboard, rules navigation, certificate action')
} finally {
  await browser.close()
}
