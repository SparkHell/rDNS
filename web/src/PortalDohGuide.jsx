import React from 'react'

const linuxConfig = `listen-addrs:
  - 127.0.0.1
listen-ports:
  - 53
upstream:
  - '粘贴完整的个人 DoH URL'
bootstrap:
  - '替换为可用的 DNS IP:53'`

const systemGuides = [
  {
    name: 'Android',
    steps: [
      '打开 AdGuard for Android，进入「保护 → DNS 保护 → DNS 服务器」，选择「添加 DNS 服务器」。',
      '粘贴完整的个人 DoH URL，保存并选中新增的服务器。开启 DNS 保护并允许 Android 创建本地 VPN。',
    ],
    note: 'Android 系统「私人 DNS」只接受主机名，无法填入带路径的个人 URL。其他 VPN 正在运行时，可改用下方的 Chrome 浏览器配置。',
    source: 'https://kb.adguard.com/kb/adguard-for-android/features/protection/dns-protection/',
  },
  {
    name: 'Windows 11',
    steps: [
      '向管理员获取与个人 DoH 地址对应的服务入口 IP。打开「设置 → 网络和 Internet → 当前 Wi-Fi 或以太网」，在「DNS 服务器分配」旁选择「编辑」。',
      '选择「手动」，启用与入口 IP 对应的 IPv4 或 IPv6，并在「首选 DNS」中填入该 IP。',
      '在「DNS over HTTPS」中选择「打开（手动模板）」，将完整的个人 DoH URL 填入模板，关闭明文回退并保存。',
    ],
    note: '设置按网络连接保存。没有入口 IP 或手动模板选项时，可以使用浏览器配置。',
    source: 'https://support.microsoft.com/en-gb/windows/experience/connectivity-networking/essential-network-settings-and-tasks-in-windows',
  },
  {
    name: 'macOS',
    steps: [
      <><a href="/portal/api/rdns.mobileconfig">下载 macOS 描述文件</a>，然后打开下载的 <code>rdns.mobileconfig</code>。</>,
      '进入「系统设置 → 通用 → 设备管理」，在「已下载」中打开 rDns 个人 DNS 并安装。旧版 macOS 可在系统设置中搜索「描述文件」。',
    ],
    source: 'https://support.apple.com/zh-cn/guide/mac-help/mh35561/mac',
  },
  {
    name: 'iOS / iPadOS',
    steps: [
      '在上方点击「扫码安装 iOS 描述文件」，用 iPhone 或 iPad 相机扫码。在当前设备上配置时，可直接打开二维码旁的下载链接。',
      '允许下载后，前往「设置 → 已下载描述文件」，选择 rDns 个人 DNS 并安装。',
    ],
  },
  {
    name: 'Linux',
    steps: [
      <>安装 <a href="https://github.com/AdguardTeam/dnsproxy/releases" rel="noreferrer">AdGuard dnsproxy</a>。将以下内容保存为仅自己可读的 <code>dnsproxy.yaml</code>，填入完整的个人 DoH URL 和可独立访问的引导 DNS。引导 DNS 用于解析 DoH 服务器的主机名，不能指向本机代理。</>,
      <>在配置文件所在目录运行 <code>sudo dnsproxy --config-path ./dnsproxy.yaml</code>。代理监听 <code>127.0.0.1:53</code>，请先确认该地址和端口可用，并保持代理运行。</>,
      <>在当前网络连接中关闭 IPv4 和 IPv6 的自动 DNS，将 IPv4 DNS 设为 <code>127.0.0.1</code>。需要开机自动使用时，将 dnsproxy 配置为系统服务。停止代理前，先恢复原来的 DNS 设置。</>,
    ],
    config: linuxConfig,
    source: 'https://github.com/AdguardTeam/dnsproxy#usage',
  },
]

const browserGuides = [
  {
    name: 'Chrome',
    steps: [
      '桌面版进入「设置 → 隐私和安全 → 安全 → 使用安全 DNS」。Android 版进入「设置 → 隐私和安全 → 使用安全 DNS」。',
      '启用安全 DNS，选择自定义提供商，然后粘贴完整的个人 DoH URL。',
    ],
    source: 'https://support.google.com/chrome/answer/10468685?hl=zh-Hans',
  },
  {
    name: 'Microsoft Edge',
    steps: [
      '打开桌面版「设置 → 隐私、搜索和服务 → 安全性」。找到并打开「使用安全 DNS」。',
      '选择「选择服务提供商」，在输入框中粘贴完整的个人 DoH URL。',
    ],
    source: 'https://learn.microsoft.com/zh-cn/legal/microsoft-edge/privacy#secure-dns',
  },
  {
    name: 'Firefox',
    steps: [
      '打开桌面版「设置 → 隐私与安全」，找到「基于 HTTPS 的 DNS」。如果有「高级设置」，先打开它。',
      '有「自定义保护」时，选中它并开启「安全 DNS 不可用时始终警告我」。旧版可选择「最大保护」。在提供商列表中选择「自定义」，粘贴完整的个人 DoH URL。',
    ],
    source: 'https://support.mozilla.org/zh-CN/kb/dns-over-https',
  },
  {
    name: 'Safari',
    steps: ['按 macOS 或 iOS / iPadOS 指南安装系统 DNS 描述文件。Safari 通过系统 DNS 配置使用个人 DoH。'],
    note: '启用 iCloud 专用代理时，Safari 的部分查询可能由专用代理处理。',
    source: 'https://support.apple.com/zh-cn/102602',
  },
]

function GuideGroup({ title, guides }) {
  return <section className="portal-guide-group">
    <h3>{title}</h3>
    {guides.map(({ name, steps, note, config, source }) => <details key={name}>
      <summary>{name}</summary>
      <div className="portal-guide-content">
        <ol>{steps.map((step, index) => <li key={index}>
          {step}
          {config && index === 0 && <pre><code>{config}</code></pre>}
        </li>)}</ol>
        {note && <p>{note}</p>}
        {source && <p><a href={source} rel="noreferrer">官方说明</a></p>}
      </div>
    </details>)}
  </section>
}

export function PortalDohGuide() {
  return <section className="panel portal-doh-guide" aria-labelledby="portal-doh-guide-title">
    <h2 id="portal-doh-guide-title">DoH 配置指南</h2>
    <p className="portal-hint">需要填写 URL 时，使用上方「复制地址」获取完整的个人地址。浏览器内设置通常只影响该浏览器的查询。</p>
    <div className="portal-guide-groups">
      <GuideGroup title="操作系统" guides={systemGuides} />
      <GuideGroup title="浏览器" guides={browserGuides} />
    </div>
    <p className="portal-hint">配置后，用对应设备或浏览器打开一个近期未访问的网站，再刷新本页，在「查询明细」中查找该域名。</p>
  </section>
}
