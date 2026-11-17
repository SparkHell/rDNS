import React, { useState } from 'react'

const splitLines = text => text.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
const modeNames = { open: '开放模式', whitelist: '白名单模式', blacklist: '黑名单模式' }
const timeLabel = value => value ? new Date(value * 1000).toLocaleString() : '尚未更新'

export function FeatureIcon({ kind }) {
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{kind === 'geo' ? <><circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/></> : kind === 'list' ? <><path d="M5 3h14v18H5zM9 8h6M9 12h6M9 16h4"/></> : <><path d="M4 5h6v5H4zM14 14h6v5h-6zM7 10v7h7M17 14V7h-7"/></>}</svg>
}

function Section({ title, description, children }) {
  return <section className="panel"><div className="panel-head"><div><h2>{title}</h2><p>{description}</p></div></div><div className="policy-body">{children}</div></section>
}

function GroupSelect({ label, value, groups, onChange }) {
  return <label>{label}<select value={value} onChange={event => onChange(event.target.value)}><option value="">请选择上游组</option>{groups.map(group => <option key={group.name} value={group.name}>{group.name}</option>)}</select></label>
}

export default function FeaturePages({ page, status, draft, setDraft, isAdmin, busy, save, command, lookup }) {
  const [ip, setIp] = useState('')
  const [lookupResult, setLookupResult] = useState(null)
  if (!status || !draft) return <div className="empty">正在获取策略配置…</div>
  if (!isAdmin) return <Section title="策略状态" description="配置由管理员维护"><p>客户端：{modeNames[status.settings.access.mode]}</p><p>GFWList：{status.gfwlist.count} 条可用规则</p><p>IPv4 数据库：{status.geo.ipv4.available ? '可用' : '未加载'}；IPv6 数据库：{status.geo.ipv6.available ? '可用' : '未加载'}</p></Section>
  const update = (key, patch) => setDraft(previous => ({ ...previous, [key]: { ...previous[key], ...patch } }))
  const group = (index, patch) => setDraft(previous => ({ ...previous, groups: previous.groups.map((item, i) => i === index ? { ...item, ...patch } : item) }))
  const saved = JSON.stringify(draft) === JSON.stringify(status.settings)
  const footer = <div className="policy-actions"><span role="status">{saved ? '配置已保存' : '有未保存的修改'}</span><button className="btn tertiary" type="button" disabled={busy || saved} onClick={() => setDraft(structuredClone(status.settings))}>恢复已保存配置</button><button className="btn primary" type="button" disabled={busy} onClick={save}>{busy ? '正在处理…' : '保存并立即应用'}</button></div>
  return <div className="policy-editor">
    {page === 'clients' && <>
      <Section title="客户端访问模式" description="网段和地区条件必须同时通过；所有 DNS 接入协议共用此策略">
        <fieldset className="policy-modes"><legend>访问模式</legend>{[['open', '开放模式', '允许所有来源网段'], ['whitelist', '白名单模式', '仅允许列表中的网段'], ['blacklist', '黑名单模式', '拒绝列表中的网段']].map(([value, label, description]) => <label key={value}><input type="radio" name="access-mode" value={value} checked={draft.access.mode === value} onChange={() => update('access', { mode: value })}/><span><strong>{label}</strong><small>{description}</small></span></label>)}</fieldset>
        {draft.access.mode !== 'open' && <label>{draft.access.mode === 'whitelist' ? '允许的网段' : '禁止的网段'}<textarea rows={5} spellCheck="false" value={draft.access.cidrs.join('\n')} onChange={event => update('access', { cidrs: event.target.value.split('\n') })} placeholder={'192.168.0.0/16\n2001:db8::/32'}/><small>每行一个 IPv4 或 IPv6 CIDR。</small></label>}
      </Section>
      <Section title="地区访问规则" description="按来源 IP 的国家/地区及省级行政区判断">
        <div className="policy-grid"><label>地区策略<select value={draft.access.region_mode} onChange={event => update('access', { region_mode: event.target.value })}><option value="any">不限制地区</option><option value="allow">仅允许指定地区</option><option value="block">禁止指定地区</option></select></label>{draft.access.region_mode !== 'any' && <label>内网及无法识别的 IP<select value={draft.access.allow_unknown ? 'allow' : 'deny'} onChange={event => update('access', { allow_unknown: event.target.value === 'allow' })}><option value="deny">拒绝访问</option><option value="allow">允许访问</option></select></label>}</div>
        {draft.access.region_mode !== 'any' && <><p className="policy-help">国家可填写代码（如 CN）或数据库中的名称；省级行政区留空代表整个国家/地区。名称以 IP 查询结果为准。</p>{draft.access.regions.map((rule, index) => <div className="region-row" key={index}><label>国家/地区<input value={rule.country} placeholder="CN" onChange={event => update('access', { regions: draft.access.regions.map((item, i) => i === index ? { ...item, country: event.target.value } : item) })}/></label><label>省级行政区（可选）<input value={rule.province} placeholder="广东省" onChange={event => update('access', { regions: draft.access.regions.map((item, i) => i === index ? { ...item, province: event.target.value } : item) })}/></label><button className="text-button danger" type="button" onClick={() => update('access', { regions: draft.access.regions.filter((_, i) => i !== index) })}>删除地区</button></div>)}<button className="btn tertiary" type="button" onClick={() => update('access', { regions: [...draft.access.regions, { country: '', province: '' }] })}>添加地区</button></>}
      </Section>
      <Section title="反向代理来源识别" description="只有可信代理提供的来源地址才参与访问控制与统计"><label>可信代理网段<textarea rows={3} spellCheck="false" value={draft.access.trusted_proxies.join('\n')} onChange={event => update('access', { trusted_proxies: event.target.value.split('\n') })} placeholder={'127.0.0.1/32\n::1/128'}/><small>经 Caddy/Nginx 接入 DoH 时填写其网段，并让代理正确设置 X-Forwarded-For。直接接入可留空。</small></label></Section>
    </>}
    {page === 'upstreams' && <>
      <Section title="默认解析策略" description="缓存命中直接返回；未命中时按所选模式查询">
        <div className="policy-grid"><label>解析模式<select value={draft.resolution.mode} onChange={event => update('resolution', { mode: event.target.value })}><option value="recursive">仅本地递归</option><option value="doh">仅 DoH 上游</option><option value="parallel">递归优先，DoH 并行兜底</option></select></label><GroupSelect label="默认 DoH 上游组" value={draft.resolution.group} groups={draft.groups} onChange={value => update('resolution', { group: value })}/><label>总超时（毫秒）<input type="number" min="100" max="60000" value={draft.resolution.timeout_ms} onChange={event => update('resolution', { timeout_ms: Number(event.target.value) })}/></label>{draft.resolution.mode === 'parallel' && <label>递归优先等待（毫秒）<input type="number" min="0" max={draft.resolution.timeout_ms} value={draft.resolution.priority_ms} onChange={event => update('resolution', { priority_ms: Number(event.target.value) })}/></label>}</div>
        <label className="policy-check"><input type="checkbox" checked={draft.resolution.validate_dnssec} onChange={event => update('resolution', { validate_dnssec: event.target.checked })}/>本地验证 DoH 答案的 DNSSEC</label><p className="policy-help">关闭后信任所配置的 DoH 上游，转发答案不标记为本地已验证。HTTPS/SVCB 与 ECH 参数完整保留。</p>
      </Section>
      <Section title="DoH 上游组" description="组内按查询轮询；请求失败时切换其他源，暂时避让失败的源">
        {draft.groups.map((item, index) => <div className="upstream-group" key={index}><div className="policy-grid"><label>组名称<input value={item.name} onChange={event => group(index, { name: event.target.value })}/></label><label>组查询超时（毫秒）<input type="number" min="100" max="30000" value={item.timeout_ms} onChange={event => group(index, { timeout_ms: Number(event.target.value) })}/></label><label className="full-width">代理地址（可选）<input type="password" autoComplete="new-password" value={item.proxy} placeholder="http://127.0.0.1:7890 或 socks5://127.0.0.1:1080" onChange={event => group(index, { proxy: event.target.value })}/><small>留空直连；SOCKS5 使用代理端解析上游域名。</small></label></div>
          {item.servers.map((server, serverIndex) => <div className="upstream-source" key={serverIndex}><label>DoH 地址<input type="url" value={server.url} placeholder="https://dns.example/dns-query" onChange={event => group(index, { servers: item.servers.map((s, i) => i === serverIndex ? { ...s, url: event.target.value } : s) })}/></label><label>引导 IP（可选）<input value={server.bootstrap_ips.join(', ')} placeholder="1.1.1.1, 1.0.0.1" onChange={event => group(index, { servers: item.servers.map((s, i) => i === serverIndex ? { ...s, bootstrap_ips: event.target.value.split(',').map(v => v.trim()) } : s) })}/></label><button className="text-button danger" type="button" onClick={() => group(index, { servers: item.servers.filter((_, i) => i !== serverIndex) })}>删除源</button></div>)}
          <div className="policy-actions"><button className="btn tertiary" type="button" onClick={() => group(index, { servers: [...item.servers, { url: '', bootstrap_ips: [] }] })}>添加上游源</button><button className="text-button danger" type="button" onClick={() => setDraft(previous => ({ ...previous, groups: previous.groups.filter((_, i) => i !== index) }))}>删除上游组</button></div>
        </div>)}
        {!draft.groups.length && <p className="policy-help">尚未添加上游组。先创建组并添加 HTTPS DoH 地址。</p>}<button className="btn tertiary" type="button" onClick={() => setDraft(previous => ({ ...previous, groups: [...previous.groups, { name: previous.groups.length ? `group-${previous.groups.length + 1}` : 'default', servers: [{ url: '', bootstrap_ips: [] }], proxy: '', timeout_ms: 3000 }] }))}>添加上游组</button>
      </Section>
      <Section title="上游运行状态" description="最近一次读取的请求与失败次数"><div className="table-wrap"><table><thead><tr><th>上游组</th><th>地址</th><th>请求</th><th>失败</th></tr></thead><tbody>{status.groups.flatMap(item => item.servers.map(server => <tr key={`${item.name}-${server.url}`}><td>{item.name}</td><td>{server.url}</td><td>{server.requests}</td><td>{server.failures}</td></tr>))}</tbody></table></div></Section>
    </>}
    {page === 'gfwlist' && <Section title="GFWList 解析分流" description="特定上游组失败后转默认 DoH 组；两组均失败时返回错误，不回退本地递归">
      <label className="policy-check"><input type="checkbox" checked={draft.gfwlist.enabled} onChange={event => update('gfwlist', { enabled: event.target.checked })}/>启用 GFWList 分流</label><div className="policy-grid"><label className="full-width">名单地址<input type="url" value={draft.gfwlist.url} onChange={event => update('gfwlist', { url: event.target.value })}/></label><GroupSelect label="特定 DoH / 代理上游组" value={draft.gfwlist.group} groups={draft.groups} onChange={value => update('gfwlist', { group: value })}/><label>自动更新周期（小时）<input type="number" min="1" max="720" value={draft.gfwlist.update_hours} onChange={event => update('gfwlist', { update_hours: Number(event.target.value) })}/></label></div><p className="policy-help">默认 DoH 组：{draft.resolution.group || '未选择'}。代理在上游组中设置。自定义本地记录、过滤和条件转发优先于 GFWList。</p><dl className="policy-details"><div><dt>有效规则</dt><dd>{status.gfwlist.count.toLocaleString()}</dd></div><div><dt>未应用规则</dt><dd>{status.gfwlist.skipped}</dd></div><div><dt>上次更新</dt><dd>{timeLabel(status.gfwlist.meta?.updated_at)}</dd></div></dl><p className="policy-help">内置官方名单快照，支持 Base64、域名、通配符及可用的正则表达式。DNS 不区分 URL 路径：正向 URL 规则应用到整个主机；路径例外与无法处理的表达式计入未应用规则。</p>{status.gfwlist.meta?.error && <p className="notice error">{status.gfwlist.meta.error}</p>}<button className="btn tertiary" type="button" disabled={busy || !saved} onClick={() => command('gfwlist.refresh')}>立即更新已保存的名单源</button>
    </Section>}
    {page === 'geoip' && <>
      <Section title="来源地理数据库" description="离线 ip2region XDB，支持 IPv4 与 IPv6；有效文件加载后即时生效">
        <label className="policy-check"><input type="checkbox" checked={draft.geo.enabled} onChange={event => update('geo', { enabled: event.target.checked })}/>启用 GeoIP 查询与来源统计</label>
        {[['ipv4', 'IPv4', 4], ['ipv6', 'IPv6', 6]].map(([key, label, version]) => <div className="geo-database" key={key}><h3>{label} 数据库 <span className={`tag ${status.geo[key].available ? 'local' : 'forward'}`}>{status.geo[key].available ? '已加载' : '未加载'}</span></h3><div className="policy-grid"><label className="full-width">本地绝对路径<input value={draft.geo[`${key}_path`]} onChange={event => update('geo', { [`${key}_path`]: event.target.value })}/></label><label className="full-width">下载地址<input type="url" value={draft.geo[`${key}_url`]} onChange={event => update('geo', { [`${key}_url`]: event.target.value })}/></label></div><p className="policy-help">大小：{status.geo[key].size_bytes ? `${(status.geo[key].size_bytes / 1048576).toFixed(1)} MiB` : '—'} · 上次更新：{timeLabel(status.geo_meta?.[String(version)]?.updated_at)}</p>{status.geo_meta?.[String(version)]?.error && <p className="notice error">{status.geo_meta[String(version)].error}</p>}<button className="btn tertiary" type="button" disabled={busy || !saved} onClick={() => command('geoip.refresh', { ip_version: version })}>下载并更新 {label}</button></div>)}
        <div className="policy-grid"><label>自动更新周期（小时，0 为关闭）<input type="number" min="0" max="8760" value={draft.geo.update_hours} onChange={event => update('geo', { update_hours: Number(event.target.value) })}/></label><label>下载代理（可选）<input type="password" autoComplete="new-password" value={draft.geo.proxy} onChange={event => update('geo', { proxy: event.target.value })}/></label></div><p className="policy-help">下载或校验失败时保留上一份有效数据库。地区规则已启用但来源无法识别时，按客户端页面的未知 IP 策略处理。</p>
      </Section>
      <Section title="IP 查询与访问判断" description="检查数据库识别结果及当前已保存规则"><form className="policy-lookup" onSubmit={event => { event.preventDefault(); lookup(ip).then(setLookupResult).catch(() => {}) }}><label>来源 IP<input value={ip} onChange={event => setIp(event.target.value)} placeholder="8.8.8.8" required/></label><button className="btn tertiary" disabled={busy}>查询 IP</button></form>{lookupResult && <div className="lookup-result" role="status"><strong>{lookupResult.allowed ? '允许访问' : '拒绝访问'}</strong><p>{[lookupResult.location.country, lookupResult.location.province, lookupResult.location.city, lookupResult.location.isp].filter(Boolean).join(' · ') || '未知 / 内网地址'}</p>{lookupResult.reason && <small>{lookupResult.reason}</small>}</div>}</Section>
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
