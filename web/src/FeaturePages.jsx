import React, { useState } from 'react'

const splitLines = text => text.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
const modeNames = { open: '开放模式', whitelist: '白名单模式', blacklist: '黑名单模式' }
const accessReasons = {
  client_whitelist: '该 IP 未包含在客户端白名单网段中',
  client_blacklist: '该 IP 命中客户端黑名单网段',
  region_unknown: '未能识别地区，当前策略拒绝未知来源',
  region_whitelist: '该地区未包含在允许列表中',
  region_blacklist: '该地区位于禁止列表中',
}
const timeLabel = value => value ? new Date(value * 1000).toLocaleString() : '尚未更新'

export function FeatureIcon({ kind }) {
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{kind === 'geo' ? <><circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/></> : kind === 'list' ? <><path d="M5 3h14v18H5zM9 8h6M9 12h6M9 16h4"/></> : <><path d="M4 5h6v5H4zM14 14h6v5h-6zM7 10v7h7M17 14V7h-7"/></>}</svg>
}

function Section({ title, description, action, children }) {
  return <section className="panel"><div className="panel-head"><div><h2>{title}</h2><p>{description}</p></div>{action}</div><div className="policy-body">{children}</div></section>
}

function RefreshButton({ command, type, version, children }) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  async function refresh() {
    setPending(true)
    setError('')
    try {
      await command(type, version ? { ip_version: version } : {})
    } catch (cause) {
      setError(cause.message)
    } finally {
      setPending(false)
    }
  }
  return <div><button className="btn tertiary" type="button" disabled={pending} onClick={refresh}>{pending ? '更新中…' : children}</button>
    {error && <p className="notice error" role="alert">{error}</p>}
  </div>
}

export function SourceUpload({ source, label, accept, command }) {
  const [file, setFile] = useState(null)
  const [pending, setPending] = useState(false)
  const [notice, setNotice] = useState(null)

  async function submit(event) {
    event.preventDefault()
    if (!file || pending) return
    const form = event.currentTarget
    setPending(true)
    setNotice(null)
    try {
      await command(source, file)
      form.reset()
      setFile(null)
      setNotice({ text: '已上传并加载' })
    } catch (error) {
      setNotice({ text: error.message, error: true })
    } finally {
      setPending(false)
    }
  }

  return <form className="source-upload" onSubmit={submit}>
    <label>{label}
      <input type="file" accept={accept} disabled={pending} onChange={event => {
        setFile(event.currentTarget.files[0] || null)
        setNotice(null)
      }}/>
    </label>
    <button className="btn tertiary" disabled={!file || pending}>{pending ? '上传中…' : '上传并加载'}</button>
    {notice && <p className={notice.error ? 'notice error' : 'policy-help'}
      role={notice.error ? 'alert' : 'status'}>{notice.text}</p>}
  </form>
}

function ManualSourceStatus({ meta }) {
  return meta?.manual && <p className="policy-help">正在使用手动上传的文件。成功下载更新后恢复自动订阅。</p>
}

function ProxyTest({ address, test }) {
  const [testing,setTesting] = useState(false)
  const [message,setMessage] = useState('')
  async function run() {
    setTesting(true)
    setMessage('')
    try {
      const {elapsed_ms} = await test(address)
      setMessage(`代理连接成功，HTTPS 请求用时 ${elapsed_ms} ms`)
    } catch (error) {
      setMessage(error.message)
    } finally {
      setTesting(false)
    }
  }
  return <div className="policy-actions"><button type="button" className="btn tertiary" disabled={testing || !address.trim()} onClick={run}>{testing ? '测试中…' : '测试代理'}</button><span role="status">{message}</span></div>
}

function ProxyToggle({ label, item, change }) {
  return <label className="policy-check"><input type="checkbox" checked={Boolean(item.use_proxy || item.proxy)}
    onChange={e=>change({use_proxy:e.target.checked,...(item.proxy ? {proxy:''} : {})})}/>{label}
    {item.proxy && <small>使用原有代理地址，重新勾选可切换至全局代理。</small>}</label>
}

function GroupSelect({ label, value, groups, onChange }) {
  return <label>{label}<select value={value} onChange={event => onChange(event.target.value)}><option value="">请选择上游组</option>{groups.map(group => <option key={group.name} value={group.name}>{group.name}</option>)}</select></label>
}

export default function FeaturePages({ page, status, draft, setDraft, isAdmin, busy, save, command, upload, lookup, testProxy }) {
  const [ip, setIp] = useState('')
  const [lookupResult, setLookupResult] = useState(null)
  if (!status || !draft) return <div className="empty">正在获取策略配置…</div>
  if (!isAdmin) return <Section title="策略状态" description="配置由管理员维护"><p>客户端：{modeNames[status.settings.access.mode]}</p><p>AdGuard：{status.adguard.count} 条拦截规则</p><p>GFWList：{status.gfwlist.count} 条可用规则</p><p>IPv4 数据库：{status.geo.ipv4.available ? '可用' : '未加载'}；IPv6 数据库：{status.geo.ipv6.available ? '可用' : '未加载'}</p></Section>
  const update = (key, patch) => setDraft(previous => ({ ...previous, [key]: { ...previous[key], ...patch } }))
  const group = (index, patch) => setDraft(previous => ({ ...previous, groups: previous.groups.map((item, i) => i === index ? { ...item, ...patch } : item) }))
  const renameGroup = (index, name) => setDraft(previous => {
    const old = previous.groups[index].name
    return {
      ...previous,
      groups: previous.groups.map((item,i) => i === index ? {...item,name} : item),
      resolution: previous.resolution.group === old ? {...previous.resolution,group:name} : previous.resolution,
      gfwlist: previous.gfwlist.group === old ? {...previous.gfwlist,group:name} : previous.gfwlist,
    }
  })
  const saved = JSON.stringify(draft) === JSON.stringify(status.settings)
  const footer = <div className="policy-actions"><span role="status">{saved ? '配置已保存' : '有未保存的修改'}</span><button className="btn tertiary" type="button" disabled={busy || saved} onClick={() => setDraft(structuredClone(status.settings))}>恢复已保存配置</button><button className="btn primary" type="button" disabled={busy} onClick={save}>{busy ? '正在处理…' : '保存并立即应用'}</button></div>
  return <div className={page === 'subscriptions' ? 'policy-editor subscription-editor' : 'policy-editor'}>
    {page === 'clients' && <>
      <Section title="客户端访问模式" description="网段和地区条件必须同时通过；所有 DNS 接入协议共用此策略">
        <fieldset className="policy-modes"><legend>访问模式</legend>{[['open', '开放模式', '允许所有来源网段'], ['whitelist', '白名单模式', '仅允许列表中的网段'], ['blacklist', '黑名单模式', '拒绝列表中的网段']].map(([value, label, description]) => <label key={value}><input type="radio" name="access-mode" value={value} checked={draft.access.mode === value} onChange={() => update('access', { mode: value })}/><span><strong>{label}</strong><small>{description}</small></span></label>)}</fieldset>
        {draft.access.mode !== 'open' && <label>{draft.access.mode === 'whitelist' ? '允许的网段' : '禁止的网段'}<textarea rows={5} spellCheck="false" value={draft.access.cidrs.join('\n')} onChange={event => update('access', { cidrs: event.target.value.split('\n') })} placeholder={'192.168.0.0/16\n2001:db8::/32'}/><small>每行一个 IPv4 或 IPv6 CIDR。</small></label>}
      </Section>
      <Section title="地区访问规则" description="按来源 IP 的国家/地区及省级行政区判断">
        <div className="policy-grid"><label>地区策略<select value={draft.access.region_mode} onChange={event => update('access', { region_mode: event.target.value })}><option value="any">不限制地区</option><option value="allow">仅允许指定地区</option><option value="block">禁止指定地区</option></select></label>{draft.access.region_mode !== 'any' && <label>内网及无法识别的 IP<select value={draft.access.allow_unknown ? 'allow' : 'deny'} onChange={event => update('access', { allow_unknown: event.target.value === 'allow' })}><option value="deny">拒绝访问</option><option value="allow">允许访问</option></select></label>}</div>
        {draft.access.region_mode !== 'any' && <><p className="policy-help">国家可填写代码（如 CN）或数据库中的名称；省级行政区留空代表整个国家/地区。名称以 IP 查询结果为准。</p>{draft.access.regions.map((rule, index) => <div className="region-row" key={index}><label>国家/地区<input value={rule.country} placeholder="CN" onChange={event => update('access', { regions: draft.access.regions.map((item, i) => i === index ? { ...item, country: event.target.value } : item) })}/></label><label>省级行政区（可选）<input value={rule.province} placeholder="广东省" onChange={event => update('access', { regions: draft.access.regions.map((item, i) => i === index ? { ...item, province: event.target.value } : item) })}/></label><button className="text-button danger" type="button" onClick={() => update('access', { regions: draft.access.regions.filter((_, i) => i !== index) })}>删除地区</button></div>)}<button className="btn tertiary" type="button" onClick={() => update('access', { regions: [...draft.access.regions, { country: '', province: '' }] })}>添加地区</button></>}
      </Section>
      <Section title="反向代理来源识别" description="只有可信代理提供的来源地址才参与访问控制与统计"><label>可信代理网段<textarea rows={3} spellCheck="false" value={draft.access.trusted_proxies.join('\n')} onChange={event => update('access', { trusted_proxies: event.target.value.split('\n') })} placeholder={'127.0.0.1/32\n::1/128'}/><small>默认填写本机代理网段，可按部署需要编辑。留空后使用连接来源地址。</small></label></Section>
    </>}
    {page === 'upstreams' && <>
      <Section title="默认解析策略" description="缓存命中直接返回；未命中时按所选模式查询">
        <div className="policy-grid">
          <label>解析模式<select value={draft.resolution.mode} onChange={event => update('resolution', { mode: event.target.value })}>
            <option value="recursive">{draft.resolution.recursion_compatibility === 'strict' ? '本地递归，DoH 兜底' : '仅本地递归'}</option>
            <option value="doh">仅 DoH 上游</option><option value="parallel">递归优先，DoH 并行兜底</option>
          </select></label>
          {draft.resolution.mode !== 'doh' && <label>递归兼容模式<select value={draft.resolution.recursion_compatibility}
            onChange={event => update('resolution', { recursion_compatibility: event.target.value })}>
            <option value="relaxed">宽松（默认）</option><option value="strict">严格</option>
          </select></label>}
          <GroupSelect label="默认 DoH 上游组" value={draft.resolution.group} groups={draft.groups} onChange={value => update('resolution', { group: value })}/>
          <label>总超时（毫秒）<input type="number" min="100" max="60000" value={draft.resolution.timeout_ms} onChange={event => update('resolution', { timeout_ms: Number(event.target.value) })}/></label>
          {draft.resolution.mode === 'parallel' && <label>递归优先等待（毫秒）<input type="number" min="0" max={draft.resolution.timeout_ms} value={draft.resolution.priority_ms} onChange={event => update('resolution', { priority_ms: Number(event.target.value) })}/></label>}
        </div>
        {draft.resolution.mode !== 'doh' && <p className="policy-help">宽松模式在逐级查询遇到中间名称不存在时继续查询。严格模式在递归没有所查记录或失败时，尝试默认 DoH 上游组。</p>}
        <label className="policy-check"><input type="checkbox" checked={draft.resolution.validate_dnssec} onChange={event => update('resolution', { validate_dnssec: event.target.checked })}/>本地验证 DoH 答案的 DNSSEC</label>
        <p className="policy-help">适用于仅 DoH 上游、GFWList 路由和严格递归的 DoH 兜底。宽松模式下，DoH 并行兜底直接采用上游应答，仅本地递归在校验失败时可返回带标记的未验证应答。</p>
      </Section>
      <Section title="全局代理" description="DoH 上游组可单独选择是否使用此地址。">
        <label>全局代理地址<input type="text" spellCheck={false} autoComplete="off" value={draft.proxy_url || ''} placeholder="http://127.0.0.1:7890 或 socks5://127.0.0.1:1080"
          onChange={event=>setDraft(previous=>({...previous,proxy_url:event.target.value}))}/><small>支持 HTTP、HTTPS 和 SOCKS5；测试使用当前输入的地址访问 Cloudflare。</small></label>
        <label className="policy-check"><input type="checkbox" checked={Boolean(draft.proxy_subscriptions)} onChange={e=>setDraft(previous=>({...previous,proxy_subscriptions:e.target.checked}))}/>代理订阅源</label>
        <p className="policy-help">应用于 AdGuard、GFWList、GeoIP（IPv4 和 IPv6）及自定义过滤订阅。</p>
        <ProxyTest key={draft.proxy_url} address={draft.proxy_url || ''} test={testProxy}/>
      </Section>
      <Section title="DoH 上游组" description="查询在同组地址间轮询，失败后尝试组内其他地址。" action={<button className="btn tertiary" type="button" onClick={() => setDraft(previous => ({ ...previous, groups: [...previous.groups, { name: previous.groups.length ? `group-${previous.groups.length + 1}` : 'default', servers: [{ url: '', bootstrap_ips: [] }], use_proxy: false, timeout_ms: 3000 }] }))}>添加上游组</button>}>
        {draft.groups.map((item, index) => <div className="upstream-group" key={index}>
          <div className="upstream-heading"><h3>{item.name || '未命名组'}</h3><button className="text-button danger" type="button" onClick={() => setDraft(previous => ({ ...previous, groups: previous.groups.filter((_, i) => i !== index) }))}>删除此组</button></div>
          <div className="policy-grid"><label>组名称<input value={item.name} onChange={event => renameGroup(index, event.target.value)}/></label><label>组查询超时（毫秒）<input type="number" min="100" max="30000" value={item.timeout_ms} onChange={event => group(index, { timeout_ms: Number(event.target.value) })}/></label><ProxyToggle label="此 DoH 组使用全局代理" item={item} change={patch=>group(index,patch)}/></div>
          <div className="upstream-addresses"><div className="upstream-heading"><h4>组内 DoH 地址</h4><button className="btn tertiary" type="button" onClick={() => group(index, { servers: [...item.servers, { url: '', bootstrap_ips: [] }] })}>添加地址</button></div>
          {item.servers.map((server, serverIndex) => <div className="upstream-source" key={serverIndex}><label>DoH 地址<input type="url" value={server.url} placeholder="https://dns.example/dns-query" onChange={event => group(index, { servers: item.servers.map((s, i) => i === serverIndex ? { ...s, url: event.target.value } : s) })}/></label><label>引导 IP（可选）<input value={server.bootstrap_ips.join(', ')} placeholder="1.1.1.1, 1.0.0.1" onChange={event => group(index, { servers: item.servers.map((s, i) => i === serverIndex ? { ...s, bootstrap_ips: event.target.value.split(',').map(v => v.trim()) } : s) })}/></label><button className="text-button danger" type="button" onClick={() => group(index, { servers: item.servers.filter((_, i) => i !== serverIndex) })}>移除地址</button></div>)}
          </div>
        </div>)}
        {!draft.groups.length && <p className="policy-help">暂无上游组。</p>}
      </Section>
      <Section title="上游运行状态" description="最近一次读取的请求与失败次数"><div className="table-wrap"><table><thead><tr><th>上游组</th><th>地址</th><th>请求</th><th>失败</th></tr></thead><tbody>{status.groups.flatMap(item => item.servers.map(server => <tr key={`${item.name}-${server.url}`}><td>{item.name}</td><td>{server.url}</td><td>{server.requests}</td><td>{server.failures}</td></tr>))}</tbody></table></div></Section>
    </>}
    {page === 'subscriptions' && !saved && <p className="policy-help">更新使用已保存的来源配置。修改下载地址后，请先保存再更新。</p>}
    {page === 'subscriptions' && <Section title="AdGuard 广告过滤" description="维护广告过滤订阅，由用户在个人 DoH 中选择启用">

      <label className="policy-check"><input type="checkbox" checked={draft.adguard.enabled} onChange={e => update('adguard',{enabled:e.target.checked})}/>向用户开放 AdGuard 过滤</label>
      <div className="policy-grid">{draft.adguard.urls.map((url,i) => <label key={i}>{i ? 'AdAway 地址' : '主要订阅地址'}<input type="url" value={url} onChange={e => update('adguard',{urls:draft.adguard.urls.map((item,j)=>j===i ? e.target.value : item)})}/></label>)}
      <label>AdGuard 更新周期（小时）<input type="number" min="1" max="720" value={draft.adguard.update_hours} onChange={e=>update('adguard',{update_hours:Number(e.target.value)})}/></label></div>
      <div className="row-actions">
        <button type="button" className="btn tertiary" disabled={busy || draft.adguard.urls[0] === 'https://anti-ad.net/easylist.txt'}
          onClick={() => update('adguard', { urls: ['https://anti-ad.net/easylist.txt', draft.adguard.urls[1]] })}>
          使用 anti-AD（AdGuard Home）
        </button>
      </div>
      <p>{status.adguard.count.toLocaleString()} 条拦截 · {status.adguard.exceptions.toLocaleString()} 条例外 · {status.adguard.skipped.toLocaleString()} 条跳过 · {timeLabel(status.adguard.meta?.updated_at)}</p>
      <p className="policy-help">支持域名、通配符、正则和常见 Hosts 条目，也支持例外规则。带修饰符或无法解析的规则会跳过。</p>
      {status.adguard.meta?.error && <p className="notice error">{status.adguard.meta.error}</p>}
      <ManualSourceStatus meta={status.adguard.meta}/><div className="source-actions"><RefreshButton command={command} type="adguard.refresh">立即更新 AdGuard</RefreshButton><SourceUpload source="adguard" label="上传 AdGuard 规则" accept=".txt,.list,.conf" command={upload}/></div>
    </Section>}
    {page === 'subscriptions' && <Section title="GFWList 解析分流" description="维护名单和上游组，由用户在个人 DoH 中选择启用">

      <label className="policy-check"><input type="checkbox" checked={draft.gfwlist.enabled} onChange={event => update('gfwlist', { enabled: event.target.checked })}/>向用户开放 GFWList 分流</label><div className="policy-grid"><label className="full-width">名单地址<input type="url" value={draft.gfwlist.url} onChange={event => update('gfwlist', { url: event.target.value })}/></label><GroupSelect label="特定 DoH / 代理上游组" value={draft.gfwlist.group} groups={draft.groups} onChange={value => update('gfwlist', { group: value })}/><label>自动更新周期（小时）<input type="number" min="1" max="720" value={draft.gfwlist.update_hours} onChange={event => update('gfwlist', { update_hours: Number(event.target.value) })}/></label></div><p className="policy-help">默认 DoH 组：{draft.resolution.group || '未选择'}。特定上游组失败后转默认 DoH 组，两组均失败时返回错误。</p><dl className="policy-details"><div><dt>有效规则</dt><dd>{status.gfwlist.count.toLocaleString()}</dd></div><div><dt>未应用规则</dt><dd>{status.gfwlist.skipped}</dd></div><div><dt>上次更新</dt><dd>{timeLabel(status.gfwlist.meta?.updated_at)}</dd></div></dl><p className="policy-help">内置官方名单快照，支持 Base64、域名、通配符及可用的正则表达式。DNS 不区分 URL 路径：正向 URL 规则应用到整个主机；路径例外与无法处理的表达式计入未应用规则。</p>{status.gfwlist.meta?.error && <p className="notice error">{status.gfwlist.meta.error}</p>}<ManualSourceStatus meta={status.gfwlist.meta}/><div className="source-actions"><RefreshButton command={command} type="gfwlist.refresh">立即更新 GFWList</RefreshButton><SourceUpload source="gfwlist" label="上传 GFWList 名单" accept=".txt,.list,.conf,.b64" command={upload}/></div>
    </Section>}
    {page === 'subscriptions' && <>
      <Section title="GeoIP 来源地区" description="离线 ip2region XDB，支持 IPv4 与 IPv6；有效文件加载后即时生效">
        <label className="policy-check"><input type="checkbox" checked={draft.geo.enabled} onChange={event => update('geo', { enabled: event.target.checked })}/>启用 GeoIP 查询与来源统计</label>
        {[['ipv4', 'IPv4', 4], ['ipv6', 'IPv6', 6]].map(([key, label, version]) => <div className="geo-database" key={key}><h3>{label} 数据库 <span className={`tag ${status.geo[key].available ? 'local' : 'forward'}`}>{status.geo[key].available ? '已加载' : '未加载'}</span></h3><div className="policy-grid"><label className="full-width">本地绝对路径<input value={draft.geo[`${key}_path`]} onChange={event => update('geo', { [`${key}_path`]: event.target.value })}/></label><label className="full-width">下载地址<input type="url" value={draft.geo[`${key}_url`]} onChange={event => update('geo', { [`${key}_url`]: event.target.value })}/></label></div><p className="policy-help">大小：{status.geo[key].size_bytes ? `${(status.geo[key].size_bytes / 1048576).toFixed(1)} MiB` : '—'} · 上次更新：{timeLabel(status.geo_meta?.[String(version)]?.updated_at)}</p>{status.geo_meta?.[String(version)]?.error && <p className="notice error">{status.geo_meta[String(version)].error}</p>}<ManualSourceStatus meta={status.geo_meta?.[String(version)]}/><div className="source-actions"><RefreshButton command={command} type="geoip.refresh" version={version}>下载并更新 {label}</RefreshButton><SourceUpload source={`geoip${version}`} label={`上传 ${label} XDB`} accept=".xdb" command={upload}/></div></div>)}
        <div className="policy-grid"><label>自动更新周期（小时，0 为关闭）<input type="number" min="0" max="8760" value={draft.geo.update_hours} onChange={event => update('geo', { update_hours: Number(event.target.value) })}/></label></div><p className="policy-help">下载或校验失败时保留上一份有效数据库。地区规则已启用但来源无法识别时，按客户端页面的未知 IP 策略处理。</p>
      </Section>
      <Section title="IP 查询与访问判断" description="检查数据库识别结果及当前已保存规则"><form className="policy-lookup" onSubmit={event => { event.preventDefault(); lookup(ip).then(setLookupResult).catch(() => {}) }}><label>来源 IP<input value={ip} onChange={event => setIp(event.target.value)} placeholder="8.8.8.8" required/></label><button className="btn tertiary" disabled={busy}>查询 IP</button></form>{lookupResult && <div className="lookup-result" role="status"><strong>{lookupResult.ip} 的归属地</strong><p>{[lookupResult.location.country, lookupResult.location.province, lookupResult.location.city, lookupResult.location.isp].filter(Boolean).join(' · ') || '未知 / 内网地址'}</p><p>模拟客户端访问 rDns：{lookupResult.allowed ? '允许' : '拒绝'}</p>{lookupResult.reason && <small>{accessReasons[lookupResult.reason] || lookupResult.reason}</small>}</div>}</Section>
    </>}
    {footer}
  </div>
}

export function cleanFeatureSettings(draft) {
  const settings = structuredClone(draft)
  settings.access.cidrs = settings.access.cidrs.map(s => s.trim()).filter(Boolean)
  settings.access.trusted_proxies = settings.access.trusted_proxies.map(s => s.trim()).filter(Boolean)
  settings.groups.forEach(group => group.servers.forEach(server => { server.bootstrap_ips = splitLines(server.bootstrap_ips.join(',')) }))
  return settings
}

export function RegionStats({ regions = [] }) {
  return <section className="panel"><div className="panel-head"><div><h2>查询来源地区</h2><p>按保留期内的请求统计，包含被访问策略拒绝的请求</p></div></div><div className="table-wrap"><table><thead><tr><th>国家/地区</th><th>省级行政区</th><th>查询次数</th></tr></thead><tbody>{regions.map((item, index) => <tr key={index}><td>{item.country}</td><td>{item.province}</td><td>{item.count.toLocaleString()}</td></tr>)}</tbody></table></div></section>
}
