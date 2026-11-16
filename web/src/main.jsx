import React, { useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'

const NAV = [
  ['overview', '概览', '◫'],
  ['logs', '查询日志', '≡'],
  ['rules', '解析与过滤', '◈'],
  ['subscriptions', '订阅源', '▤'],
  ['listeners', '监听服务', '◉'],
  ['cache', '缓存', '▣'],
  ['clients', '客户端', '◎'],
  ['certificates', '证书', '◇'],
  ['accounts', '管理员', '♙'],
]

async function api(path, token, options = {}) {
  const response = await fetch(`/api/v1${path}`, {
    ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers },
  })
  if (!response.ok) throw new Error(await response.text() || `HTTP ${response.status}`)
  return response.json()
}

function App() {
  const [token, setToken] = useState(sessionStorage.getItem('rdns-token') || '')
  const [me, setMe] = useState(null)
  const [page, setPage] = useState('overview')
  const [stats, setStats] = useState({ total: 0, blocked: 0 })
  const [logs, setLogs] = useState([])
  const [rules, setRules] = useState([])
  const [subscriptions, setSubscriptions] = useState([])
  const [clients, setClients] = useState([])
  const [cidrText, setCidrText] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [login, setLogin] = useState({ username: '', password: '' })
  const [rule, setRule] = useState({ kind: 'local', domain: '', record_type: 'A', value: '', ttl: 300 })
  const [url, setUrl] = useState('')
  const [account, setAccount] = useState({ username: '', password: '', role: 'viewer' })
  const [accounts, setAccounts] = useState([])
  const [audit, setAudit] = useState([])
  const [certPaths, setCertPaths] = useState({ certificate: '', private_key: '' })
  const [listenerStatus, setListenerStatus] = useState(null)
  const [listenerDraft, setListenerDraft] = useState(null)
  const [cacheStatus, setCacheStatus] = useState(null)
  const [cacheDraft, setCacheDraft] = useState(null)
  const lastCacheSettings = useRef('')
  const socketRef = useRef(null)
  const pendingRef = useRef(new Map())
  const requestSeq = useRef(0)

  const canEdit = me?.role === 'admin' || me?.role === 'editor'
  const isAdmin = me?.role === 'admin'

  async function refresh(activeToken = token) {
    if (!activeToken) return
    try {
      const [profile, status, recent, allRules, allSubscriptions, allClients] = await Promise.all([
        api('/me', activeToken), api('/stats', activeToken), api('/logs', activeToken), api('/rules', activeToken), api('/subscriptions', activeToken), api('/clients', activeToken),
      ])
      setMe(profile); setStats(status); setLogs(recent); setRules(allRules); setSubscriptions(allSubscriptions); setClients(allClients); setCidrText(allClients.join('\n')); setError('')
      if (profile.role === 'admin') {
        const [allAccounts, events, paths] = await Promise.all([api('/accounts', activeToken), api('/audit', activeToken), api('/certificates', activeToken)])
        setAccounts(allAccounts); setAudit(events); setCertPaths(paths)
      }
    } catch (err) {
      if (err.message.includes('authentication')) { sessionStorage.removeItem('rdns-token'); setToken(''); setMe(null) }
      else setError(err.message)
    }
  }

  useEffect(() => { refresh() }, [token])
  useEffect(() => {
    if (!token) return
    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const socket = new WebSocket(`${scheme}//${location.host}/api/v1/ws`)
    socketRef.current = socket
    socket.onopen = () => socket.send(JSON.stringify({ type: 'auth', token }))
    socket.onmessage = event => {
      const message = JSON.parse(event.data)
      if (message.type === 'listeners') { setListenerStatus(message); setListenerDraft(message.settings) }
      if (message.type === 'cache') { setCacheStatus(message.stats); const saved = JSON.stringify(message.stats.settings); if (saved !== lastCacheSettings.current) { lastCacheSettings.current = saved; setCacheDraft(message.stats.settings) } }
      if (message.type === 'listener_error') { setError(`${message.protocol}: ${message.error}`); setListenerStatus(previous => previous ? { ...previous, running: { ...previous.running, [message.protocol]: false } } : previous) }
      if (message.type === 'result') {
        const pending = pendingRef.current.get(message.request_id)
        if (pending) { pendingRef.current.delete(message.request_id); message.ok ? pending.resolve(message) : pending.reject(new Error(message.error || '配置失败')) }
      }
    }
    socket.onclose = () => { if (socketRef.current === socket) socketRef.current = null; for (const pending of pendingRef.current.values()) pending.reject(new Error('实时连接已断开，请刷新页面')); pendingRef.current.clear() }
    return () => socket.close()
  }, [token])

  function sendSettings(type, settings) {
    const socket = socketRef.current
    if (!socket || socket.readyState !== WebSocket.OPEN) return Promise.reject(new Error('实时连接未就绪，请刷新页面'))
    const request_id = ++requestSeq.current
    return new Promise((resolve, reject) => {
      pendingRef.current.set(request_id, { resolve, reject })
      socket.send(JSON.stringify({ type, request_id, settings }))
    })
  }

  const saveListeners = () => sendSettings('listeners.update', listenerDraft)
  const saveCache = () => sendSettings('cache.update', cacheDraft)

  async function run(action) {
    setBusy(true); setError('')
    try { await action(); await refresh() } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  async function signIn(event) {
    event.preventDefault(); setBusy(true); setError('')
    try { const result = await api('/login', '', { method: 'POST', body: JSON.stringify(login) }); sessionStorage.setItem('rdns-token', result.token); setToken(result.token); setLogin({ username: '', password: '' }) }
    catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  function signOut() {
    api('/logout', token, { method: 'POST' }).catch(() => {})
    sessionStorage.removeItem('rdns-token'); setToken(''); setMe(null)
  }

  if (!me) return <main className="login-page"><div className="login-shell"><div className="brand brand-large"><span className="brand-mark">r</span><span>Dns<span className="brand-dot">.</span></span></div><p className="eyebrow">SECURE DNS OPERATIONS</p><h1>欢迎回来</h1><p className="muted">登录以管理企业 DNS 服务与解析策略。</p><form onSubmit={signIn} className="login-form"><label>用户名<input autoFocus autoComplete="username" value={login.username} onChange={e => setLogin({ ...login, username: e.target.value })} required /></label><label>密码<input type="password" autoComplete="current-password" value={login.password} onChange={e => setLogin({ ...login, password: e.target.value })} required /></label>{error && <div className="notice error">{error}</div>}<button className="btn primary wide" disabled={busy}>登录控制台 <span>→</span></button></form><div className="login-foot">PRIVATE RESOLVER · DNSSEC VALIDATION</div></div></main>

  return <div className="app-shell flex min-h-screen">
    <aside className="sidebar"><div className="brand"><span className="brand-mark">r</span><span>Dns<span className="brand-dot">.</span></span></div><div className="sidebar-label">工作台</div><nav>{NAV.filter(([id]) => id !== 'accounts' || isAdmin).map(([id, label, icon]) => <button key={id} className={`nav-item ${page === id ? 'active' : ''}`} onClick={() => setPage(id)}><span className="nav-icon">{icon}</span>{label}</button>)}</nav><div className="sidebar-bottom"><div className="health-dot"/>服务运行中<span className="version">v0.1</span></div></aside>
    <div className="main-area"><header className="topbar flex items-center justify-between"><div className="breadcrumb">控制台 <span>/</span> {NAV.find(([id]) => id === page)?.[1]}</div><div className="top-actions"><span className="env-badge">内部服务</span><span className="avatar">{me.username.slice(0, 1).toUpperCase()}</span><span className="username">{me.username}</span><button className="text-button" onClick={signOut}>退出</button></div></header>
      <main className="content"><div className="page-heading"><div><div className="eyebrow">RDNS / CONTROL CENTER</div><h1>{NAV.find(([id]) => id === page)?.[1]}</h1><p className="muted">{subtitle(page)}</p></div><button className="btn secondary" onClick={() => refresh()} disabled={busy}>↻ 刷新数据</button></div>{error && <div className="notice error">{error}</div>}
        {page === 'overview' && <><div className="hero"><div><span className="hero-status"><i/> DNSSEC 验证已启用</span><h2>从根开始，可信解析。</h2><p>公网域名通过根服务器迭代解析；企业规则在本地生效。</p></div><div className="hero-art"><span className="orbit orbit-one"/><span className="orbit orbit-two"/><span className="orbit-core">DNS</span></div></div><div className="metric-grid"><Metric title="总查询" value={stats.total} foot="保留期内查询" icon="↗"/><Metric title="已过滤" value={stats.blocked} foot="广告及黑名单" icon="⊘"/><Metric title="过滤率" value={`${stats.total ? Math.round(stats.blocked / stats.total * 100) : 0}%`} foot="占全部查询" icon="◉"/><Metric title="策略规则" value={rules.length} foot="本地配置" icon="◈"/></div><section className="panel"><div className="panel-head"><div><h2>最新查询</h2><p>最近的解析活动</p></div><button className="text-button blue" onClick={() => setPage('logs')}>查看全部 →</button></div><Logs rows={logs.slice(0, 7)}/></section></>}
        {page === 'logs' && <section className="panel"><div className="panel-head"><div><h2>查询活动</h2><p>最多显示最近 200 条</p></div><span className="pill">{logs.length} 条记录</span></div><Logs rows={logs}/></section>}
        {page === 'rules' && <><section className="panel"><div className="panel-head"><div><h2>规则列表</h2><p>本地记录优先，其次为过滤和条件转发</p></div><span className="pill">{rules.length} 条规则</span></div><div className="table-wrap"><table><thead><tr><th>类型</th><th>域名</th><th>记录 / 上游</th><th>TTL</th><th/></tr></thead><tbody>{rules.map(item => <tr key={item.id}><td><span className={`tag ${item.kind}`}>{kindName(item.kind)}</span></td><td className="strong">{item.domain}</td><td>{item.record_type ? `${item.record_type} · ${item.value}` : item.value || '—'}</td><td>{item.ttl || '—'}</td><td>{canEdit && <button className="text-button danger" onClick={() => run(() => api(`/rules/${item.id}`, token, { method: 'DELETE' }))}>删除</button>}</td></tr>)}{!rules.length && <Empty columns={5} text="暂无规则。添加记录或过滤规则开始使用。"/>}</tbody></table></div></section>{canEdit && <section className="panel form-panel"><div className="panel-head"><div><h2>新增规则</h2><p>变更后即时应用到新查询</p></div></div><form onSubmit={event => { event.preventDefault(); run(async () => { await api('/rules', token, { method: 'POST', body: JSON.stringify(rule) }); setRule({ kind: 'local', domain: '', record_type: 'A', value: '', ttl: 300 }) }) }} className="form-grid"><label>规则类型<select value={rule.kind} onChange={e => setRule({ ...rule, kind: e.target.value })}><option value="local">本地记录</option><option value="allow">白名单</option><option value="block">黑名单</option><option value="forward">条件转发</option></select></label><label>域名<input placeholder="example.com" value={rule.domain} onChange={e => setRule({ ...rule, domain: e.target.value })} required /></label>{rule.kind === 'local' && <label>记录类型<select value={rule.record_type} onChange={e => setRule({ ...rule, record_type: e.target.value })}><option>A</option><option>AAAA</option><option>CNAME</option><option>TXT</option></select></label>}{['local', 'forward'].includes(rule.kind) && <label>{rule.kind === 'forward' ? '上游地址' : '记录值'}<input placeholder={rule.kind === 'forward' ? '10.0.0.53:53' : '192.0.2.10'} value={rule.value} onChange={e => setRule({ ...rule, value: e.target.value })} required /></label>}{rule.kind === 'local' && <label>TTL（秒）<input type="number" min="1" max="86400" value={rule.ttl} onChange={e => setRule({ ...rule, ttl: Number(e.target.value) })}/></label>}<button className="btn primary" disabled={busy}>添加规则 →</button></form></section>}</>}
        {page === 'subscriptions' && <><section className="panel"><div className="panel-head"><div><h2>过滤订阅</h2><p>支持纯域名、hosts 和 Adblock 域名规则</p></div><span className="pill">{subscriptions.length} 个源</span></div><div className="subscription-list">{subscriptions.map(item => <div className="subscription" key={item.id}><div className="sub-icon">▤</div><div className="sub-main"><div className="strong truncate">{item.url}</div><small>{item.last_error ? `更新失败：${item.last_error}` : item.updated_at ? `最后更新 ${new Date(item.updated_at).toLocaleString()}` : '尚未更新'}</small></div>{canEdit && <div className="row-actions"><button className="btn tertiary" disabled={busy} onClick={() => run(() => api(`/subscriptions/${item.id}/refresh`, token, { method: 'POST' }))}>更新</button><button className="text-button danger" onClick={() => run(() => api(`/subscriptions/${item.id}`, token, { method: 'DELETE' }))}>删除</button></div>}</div>)}{!subscriptions.length && <div className="empty">暂无订阅源。</div>}</div></section>{canEdit && <section className="panel form-panel"><div className="panel-head"><div><h2>添加订阅源</h2><p>仅接受 HTTPS 地址；定时自动更新</p></div></div><form className="inline-form" onSubmit={event => { event.preventDefault(); run(async () => { await api('/subscriptions', token, { method: 'POST', body: JSON.stringify({ url }) }); setUrl('') }) }}><input type="url" placeholder="https://example.com/blocklist.txt" value={url} onChange={e => setUrl(e.target.value)} required/><button className="btn primary" disabled={busy}>添加订阅</button></form></section>}</>}
        {page === 'certificates' && <section className="panel certificate-panel"><div className="certificate-symbol">◇</div><span className="tag local">TLS CERTIFICATE</span><h2>安全连接证书</h2><p>DoH、DoT 和 DoQ 共用一组 PEM 证书。填写服务器上的绝对路径并保存；服务会先验证证书与私钥，再更新新连接使用的证书。替换同一路径下的文件后，使用重载按钮重新读取。</p>{isAdmin && <><form className="cert-path-form" onSubmit={event => { event.preventDefault(); run(() => api('/certificates', token, { method: 'PUT', body: JSON.stringify(certPaths) })) }}><label>证书链路径<input type="text" autoComplete="off" placeholder="/opt/rDns/certs/fullchain.pem" value={certPaths.certificate} onChange={e => setCertPaths({ ...certPaths, certificate: e.target.value })} required /></label><label>私钥路径<input type="text" autoComplete="off" placeholder="/opt/rDns/certs/privkey.pem" value={certPaths.private_key} onChange={e => setCertPaths({ ...certPaths, private_key: e.target.value })} required /></label><button className="btn primary" disabled={busy}>保存路径并应用</button></form><button className="btn tertiary" disabled={busy} onClick={() => run(() => api('/certificates/reload', token, { method: 'POST' }))}>↻ 重载当前路径</button></>}<div className="hint">只有管理员可配置路径和重载证书；操作结果会写入审计日志。</div></section>}
        {page === 'listeners' && <section className="panel"><div className="panel-head"><div><h2>协议监听</h2><p>保存后立即生效；端口冲突会阻止本次变更并显示错误</p></div><span className="pill">实时连接</span></div>{listenerDraft ? <form className="listener-form" onSubmit={event => { event.preventDefault(); run(saveListeners) }}>{[['dns_udp','DNS · UDP','53'],['dns_tcp','DNS · TCP','53'],['doh','DoH · HTTPS','443'],['dot','DoT · TLS','853'],['doq','DoQ · QUIC','853']].map(([key,label,port]) => <div className="listener-row" key={key}><div className="listener-name"><strong>{label}</strong><small>标准端口 {port}</small></div><label className="listener-switch"><input type="checkbox" checked={listenerDraft[key].enabled} disabled={!isAdmin} onChange={e => setListenerDraft({ ...listenerDraft, [key]: { ...listenerDraft[key], enabled: e.target.checked } })}/><span>{listenerDraft[key].enabled ? '启用' : '关闭'}</span></label><input className="listener-address" aria-label={`${label} 监听地址`} type="text" value={listenerDraft[key].address} disabled={!isAdmin} onChange={e => setListenerDraft({ ...listenerDraft, [key]: { ...listenerDraft[key], address: e.target.value } })}/><span className={`tag ${listenerStatus?.running?.[key] ? 'local' : 'forward'}`}>{listenerStatus?.running?.[key] ? '运行中' : '未监听'}</span></div>)}<div className="listener-actions"><span>管理面板始终监听本机，不受这些开关影响。</span>{isAdmin && <button className="btn primary" disabled={busy}>保存并应用</button>}</div></form> : <div className="empty">正在连接实时状态…</div>}</section>}
        {page === 'cache' && <section className="panel"><div className="panel-head"><div><h2>递归缓存</h2><p>权威 NS/Glue 和答案写入 SQLite，热点使用按字节限制的内存缓存</p></div><span className="pill">实时状态</span></div>{cacheStatus && cacheDraft ? <><div className="cache-metrics"><Metric title="进程内存 RSS" value={`${(cacheStatus.process_rss_bytes / 1048576).toFixed(1)} MiB`} foot="包含运行时和 DNS 缓存" icon="◉"/><Metric title="热点缓存" value={`${(cacheStatus.memory_bytes / 1048576).toFixed(1)} MiB`} foot={`${cacheStatus.memory_entries} 条 · 命中 ${cacheStatus.memory_hits} 次 · 预算 ${cacheDraft.memory_mib} MiB`} icon="▣"/><Metric title="SQLite 缓存" value={cacheStatus.disk_entries} foot={`${(cacheStatus.disk_bytes / 1048576).toFixed(1)} MiB · 命中 ${cacheStatus.disk_hits} 次`} icon="◈"/></div><form className="cache-form" onSubmit={event => { event.preventDefault(); run(saveCache) }}><label>热点内存预算（MiB）<input type="number" min="1" max="4096" value={cacheDraft.memory_mib} disabled={!isAdmin} onChange={e => setCacheDraft({ ...cacheDraft, memory_mib: Number(e.target.value) })}/></label><label>NS/Glue 最长缓存（秒）<input type="number" min="1" max="604800" value={cacheDraft.ns_max_ttl} disabled={!isAdmin} onChange={e => setCacheDraft({ ...cacheDraft, ns_max_ttl: Number(e.target.value) })}/></label><label>正向答案最长缓存（秒）<input type="number" min="1" max="604800" value={cacheDraft.answer_max_ttl} disabled={!isAdmin} onChange={e => setCacheDraft({ ...cacheDraft, answer_max_ttl: Number(e.target.value) })}/></label><label>负向答案最长缓存（秒）<input type="number" min="1" max="604800" value={cacheDraft.negative_max_ttl} disabled={!isAdmin} onChange={e => setCacheDraft({ ...cacheDraft, negative_max_ttl: Number(e.target.value) })}/></label><p>实际缓存时间不会超过权威 TTL；DNSSEC 签名提前到期时也会提前失效。更改上限会清空旧缓存并立即按新设置运行。</p>{isAdmin && <button className="btn primary" disabled={busy}>保存缓存设置</button>}</form></> : <div className="empty">正在连接实时状态…</div>}</section>}
        {page === 'clients' && <section className="panel form-panel"><div className="panel-head"><div><h2>允许的客户端网段</h2><p>DNS 服务仅回答这些 IP 网段的请求</p></div><span className="pill">{clients.length} 个网段</span></div><div className="client-editor"><p>每行一个 IPv4 或 IPv6 CIDR。修改后立即应用到新查询。</p><textarea spellCheck="false" value={cidrText} onChange={e => setCidrText(e.target.value)} readOnly={!isAdmin}/>{isAdmin && <button className="btn primary" disabled={busy} onClick={() => run(() => api('/clients', token, { method: 'PUT', body: JSON.stringify({ cidrs: cidrText.split(/\s+/).map(s => s.trim()).filter(Boolean) }) }))}>保存网段 →</button>}</div></section>}
        {page === 'accounts' && isAdmin && <><section className="panel"><div className="panel-head"><div><h2>账号列表</h2><p>当前组织的控制台成员</p></div><span className="pill">{accounts.length} 个账号</span></div><div className="table-wrap"><table><thead><tr><th>用户名</th><th>角色</th><th/></tr></thead><tbody>{accounts.map(item => <tr key={item.id}><td className="strong">{item.username}</td><td>{({ admin: '管理员', editor: '编辑者', viewer: '只读' })[item.role]}</td><td>{item.id !== me.id && <button className="text-button danger" onClick={() => run(() => api(`/accounts/${item.id}`, token, { method: 'DELETE' }))}>删除</button>}</td></tr>)}</tbody></table></div></section><section className="panel form-panel"><div className="panel-head"><div><h2>新增管理员账号</h2><p>管理员、编辑者和只读角色</p></div></div><form className="form-grid" onSubmit={event => { event.preventDefault(); run(async () => { await api('/accounts', token, { method: 'POST', body: JSON.stringify(account) }); setAccount({ username: '', password: '', role: 'viewer' }) }) }}><label>用户名<input value={account.username} minLength={3} onChange={e => setAccount({ ...account, username: e.target.value })} required/></label><label>密码<input type="password"  value={account.password} onChange={e => setAccount({ ...account, password: e.target.value })} required/></label><label>角色<select value={account.role} onChange={e => setAccount({ ...account, role: e.target.value })}><option value="viewer">只读</option><option value="editor">编辑者</option><option value="admin">管理员</option></select></label><button className="btn primary" disabled={busy}>创建账号 →</button></form></section><section className="panel"><div className="panel-head"><div><h2>操作审计</h2><p>最近 100 条管理操作</p></div></div><div className="table-wrap"><table><thead><tr><th>时间</th><th>操作人</th><th>操作</th><th>详情</th></tr></thead><tbody>{audit.map((item, i) => <tr key={`${item.at}-${i}`}><td>{new Date(item.at).toLocaleString()}</td><td className="strong">{item.actor}</td><td>{item.action}</td><td>{item.detail}</td></tr>)}{!audit.length && <Empty columns={4} text="暂无操作记录。"/>}</tbody></table></div></section></>}
      </main></div></div>
}

function subtitle(page) { return ({ overview: '实时掌握解析流量、过滤效果与服务状态。', logs: '查看客户端查询及策略处理结果。', rules: '定义本地域名、访问策略与条件转发。', subscriptions: '集中管理广告过滤列表。', listeners: '实时启停 DNS 协议并检查端口占用。', cache: '配置内存预算与 DNS TTL 上限。', clients: '限制能够使用 DNS 服务的来源网段。', certificates: '更新加密 DNS 接入证书。', accounts: '管理控制台访问权限。' })[page] }
function kindName(kind) { return ({ local: '本地记录', allow: '白名单', block: '黑名单', forward: '条件转发' })[kind] || kind }
function Metric({ title, value, foot, icon }) { return <div className="metric"><div className="metric-top"><span>{title}</span><span className="metric-icon">{icon}</span></div><div className="metric-value">{value.toLocaleString?.() ?? value}</div><div className="metric-foot">{foot}</div></div> }
function Empty({ columns, text }) { return <tr><td colSpan={columns} className="empty">{text}</td></tr> }
function Logs({ rows }) { return <div className="table-wrap"><table><thead><tr><th>时间</th><th>查询域名</th><th>类型</th><th>客户端</th><th>协议</th><th>结果</th><th>响应时间</th></tr></thead><tbody>{rows.map((row, i) => <tr key={`${row.at}-${i}`}><td>{new Date(row.at).toLocaleString()}</td><td className="strong">{row.domain}</td><td>{row.qtype}</td><td>{row.client}</td><td>{row.protocol.toUpperCase()}</td><td><span className={`tag ${row.outcome === 'blocked' ? 'block' : row.outcome === 'error' ? 'error-tag' : 'local'}`}>{({ blocked: '已过滤', local: '本地', forward: '转发', recursive: '已解析', error: '错误', timeout: '超时' })[row.outcome] || row.outcome}</span></td><td>{row.duration_ms == null ? '—' : `${row.duration_ms.toFixed(2)} ms`}</td></tr>)}{!rows.length && <Empty columns={7} text="暂无查询记录。"/>}</tbody></table></div> }

createRoot(document.getElementById('root')).render(<App />)
