import React, { useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'
import { Portal, PortalAdmin } from './Portal.jsx'
import FeaturePages, { FeatureIcon, RegionStats, cleanFeatureSettings } from './FeaturePages.jsx'

const NAV = [
  ['overview', '概览', '◫'],
  ['logs', '查询日志', '≡'],
  ['rules', '解析与过滤', '◈'],
  ['subscriptions', '订阅源', '▤'],
  ['listeners', '监听服务', '◉'],
  ['cache', '缓存', '▣'],
  ['clients', '客户端', '◎'],
  ['upstreams', '解析上游', <FeatureIcon kind="upstream"/>],
  ['gfwlist', 'GFWList', <FeatureIcon kind="list"/>],
  ['geoip', '来源地区', <FeatureIcon kind="geo"/>],
  ['certificates', '证书', '◇'],
  ['portal', '用户门户', '◎'],
  ['accounts', '管理员', '♙'],
]

async function api(path, token, options = {}) {
  const response = await fetch(`/api/v1${path}`, {
    signal: AbortSignal.timeout(90000),
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
  const [featureStatus, setFeatureStatus] = useState(null)
  const [featureDraft, setFeatureDraft] = useState(null)
  const [success, setSuccess] = useState('')
  const lastFeatures = useRef('')
  const lastCacheSettings = useRef('')
  const lastListeners = useRef('')
  const activeSession = useRef(token)
  activeSession.current = token

  function receiveSettings(snapshot, lastSaved, setDraft) {
    const before = lastSaved.current
    lastSaved.current = JSON.stringify(snapshot)
    setDraft(previous => !previous || JSON.stringify(previous) === before ? snapshot : previous)
  }

  function receiveListeners(snapshot) {
    setListenerStatus(snapshot)
    receiveSettings(snapshot.settings, lastListeners, setListenerDraft)
  }

  function receiveCache(snapshot) {
    setCacheStatus(snapshot)
    receiveSettings(snapshot.settings, lastCacheSettings, setCacheDraft)
  }

  const canEdit = me?.role === 'admin' || me?.role === 'editor'
  const isAdmin = me?.role === 'admin'

  function receiveFeatures(message, submitted = '') {
    setFeatureStatus(message)
    const previousSaved = lastFeatures.current
    setFeatureDraft(previous => !previous || JSON.stringify(previous) === previousSaved || JSON.stringify(previous) === submitted ? message.settings : previous)
    lastFeatures.current = JSON.stringify(message.settings)
  }

  async function refresh(activeToken = token) {
    if (!activeToken) return
    try {
      const [profile, status, recent, allRules, allSubscriptions, allClients, featureState, listeners, cache] = await Promise.all([
        api('/me', activeToken), api('/stats', activeToken), api('/logs', activeToken), api('/rules', activeToken), api('/subscriptions', activeToken), api('/clients', activeToken), api('/features', activeToken), api('/listeners', activeToken), api('/cache', activeToken),
      ])
      if (activeSession.current !== activeToken) return
      receiveListeners(listeners); receiveCache(cache)
      setMe(profile); setStats(status); setLogs(recent); setRules(allRules); setSubscriptions(allSubscriptions); setClients(allClients); setCidrText(allClients.join('\n')); receiveFeatures(featureState); setError('')
      if (profile.role === 'admin') {
        const [allAccounts, events, paths] = await Promise.all([api('/accounts', activeToken), api('/audit', activeToken), api('/certificates', activeToken)])
        if (activeSession.current !== activeToken) return
        setAccounts(allAccounts); setAudit(events); setCertPaths(paths)
      }
    } catch (err) {
      if (activeSession.current !== activeToken) return
      if (err.message.includes('authentication')) clearSession()
      else setError(err.message)
    }
  }

  useEffect(() => { refresh() }, [token])
  useEffect(() => {
    if (!token) return
    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:'
    let socket, timer, stopped = false, delay = 500
    function connect() {
      socket = new WebSocket(`${scheme}//${location.host}/api/v1/ws`)
      socket.onopen = () => socket.send(JSON.stringify({ type: 'auth', token }))
      socket.onmessage = event => {
        if (stopped || activeSession.current !== token) return
        const message = JSON.parse(event.data)
        if (message.type === 'ready') delay = 500
        if (message.type === 'listeners') receiveListeners(message)
        if (message.type === 'features') receiveFeatures(message)
        if (message.type === 'cache') receiveCache(message.stats)
        if (message.type === 'listener_error') {
          setError(`${message.protocol}: ${message.error}`)
          setListenerStatus(previous => previous && { ...previous, running: { ...previous.running, [message.protocol]: false } })
        }
      }
      socket.onclose = event => {
        if (stopped || activeSession.current !== token) return
        if (event.code === 1008) {
          clearSession()
          return
        }
        timer = setTimeout(connect, delay)
        delay = Math.min(delay * 2, 10000)
      }
    }
    connect()
    return () => { stopped = true; clearTimeout(timer); socket.close() }
  }, [token])

  function writeSettings(path, method, settings) {
    return api(path, token, { method, body: JSON.stringify(settings) })
  }
  const saveListeners = () => writeSettings('/listeners', 'PUT', listenerDraft)
  const saveCache = () => writeSettings('/cache', 'PUT', cacheDraft)
  async function saveFeatures() {
    const saved = await writeSettings('/features', 'PUT', cleanFeatureSettings(featureDraft))
    if (activeSession.current === token) receiveFeatures(saved, JSON.stringify(featureDraft))
  }

  async function run(action) {
    setBusy(true); setError(''); setSuccess('')
    try { await action(); await refresh(); setSuccess('操作已完成') } catch (err) { await refresh(); setError(err.message) } finally { setBusy(false) }
  }

  async function signIn(event) {
    event.preventDefault(); setBusy(true); setError('')
    try { const result = await api('/login', '', { method: 'POST', body: JSON.stringify(login) }); sessionStorage.setItem('rdns-token', result.token); setToken(result.token); setLogin({ username: '', password: '' }) }
    catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  function signOut() {
    api('/logout', token, { method: 'POST' }).catch(() => {})
    clearSession()
  }

  function clearSession() {
    activeSession.current = ''
    sessionStorage.removeItem('rdns-token')
    setToken(''); setMe(null); setFeatureDraft(null); setFeatureStatus(null)
    setListenerDraft(null); setCacheDraft(null); setAccounts([]); setAudit([])
    lastFeatures.current = ''; lastCacheSettings.current = ''; lastListeners.current = ''
  }

  if (!me) return <main className="login-page"><div className="login-shell"><div className="brand brand-large"><span className="brand-mark">r</span><span>Dns<span className="brand-dot">.</span></span></div><p className="eyebrow">SECURE DNS OPERATIONS</p><h1>欢迎回来</h1><p className="muted">登录以管理企业 DNS 服务与解析策略。</p><form onSubmit={signIn} className="login-form"><label>用户名<input autoFocus autoComplete="username" value={login.username} onChange={e => setLogin({ ...login, username: e.target.value })} required /></label><label>密码<input type="password" autoComplete="current-password" value={login.password} onChange={e => setLogin({ ...login, password: e.target.value })} required /></label>{error && <div className="notice error">{error}</div>}<button className="btn primary wide" disabled={busy}>登录控制台 <span>→</span></button></form><div className="login-foot">PRIVATE RESOLVER · DNSSEC VALIDATION</div></div></main>

  return <div className="app-shell flex min-h-screen">
    <aside className="sidebar"><div className="brand"><span className="brand-mark">r</span><span>Dns<span className="brand-dot">.</span></span></div><div className="sidebar-label">工作台</div><nav>{NAV.filter(([id]) => !['accounts','portal'].includes(id) || isAdmin).map(([id, label, icon]) => <button key={id} className={`nav-item ${page === id ? 'active' : ''}`} onClick={() => setPage(id)}><span className="nav-icon">{icon}</span>{label}</button>)}</nav><div className="sidebar-bottom"><div className="health-dot"/>服务运行中<span className="version">v0.1</span></div></aside>
    <div className="main-area"><header className="topbar flex items-center justify-between"><div className="breadcrumb">控制台 <span>/</span> {NAV.find(([id]) => id === page)?.[1]}</div><div className="top-actions"><span className="env-badge">内部服务</span><span className="avatar">{me.username.slice(0, 1).toUpperCase()}</span><span className="username">{me.username}</span><button className="text-button" onClick={signOut}>退出</button></div></header>
      <main className="content"><div className="page-heading"><div><div className="eyebrow">RDNS / CONTROL CENTER</div><h1>{NAV.find(([id]) => id === page)?.[1]}</h1><p className="muted">{subtitle(page)}</p></div><button className="btn secondary" onClick={() => refresh()} disabled={busy}>↻ 刷新数据</button></div>{error && <div className="notice error" role="alert">{error}</div>}{success && <div className="notice success" role="status">{success}</div>}
        {['clients', 'upstreams', 'gfwlist', 'geoip'].includes(page) && <FeaturePages page={page} status={featureStatus} draft={featureDraft} setDraft={setFeatureDraft} isAdmin={isAdmin} busy={busy} save={() => run(saveFeatures)} command={(type, settings = {}) => run(() => writeSettings(type === 'gfwlist.refresh' ? '/gfwlist/refresh' : '/geoip/refresh', 'POST', settings))} lookup={ip => api('/geoip/lookup', token, { method: 'POST', body: JSON.stringify({ ip }) }).catch(error => { setError(error.message); throw error })}/>}
        {page === 'overview' && <><div className="hero"><div><span className="hero-status"><i/> {featureStatus?.settings.resolution.mode === 'doh' && !featureStatus?.settings.resolution.validate_dnssec ? 'DoH 上游解析' : 'DNSSEC 本地验证'}</span><h2>从根开始，可信解析。</h2><p>本地递归与 DoH 上游按策略解析，企业规则即时生效。</p></div><div className="hero-art"><span className="orbit orbit-one"/><span className="orbit orbit-two"/><span className="orbit-core">DNS</span></div></div><div className="metric-grid"><Metric title="总查询" value={stats.total} foot="保留期内查询" icon="↗"/><Metric title="已过滤" value={stats.blocked} foot="广告及黑名单" icon="⊘"/><Metric title="过滤率" value={`${stats.total ? Math.round(stats.blocked / stats.total * 100) : 0}%`} foot="占全部查询" icon="◉"/><Metric title="策略规则" value={rules.length} foot="本地配置" icon="◈"/></div><section className="panel"><div className="panel-head"><div><h2>最新查询</h2><p>最近的解析活动</p></div><button className="text-button blue" onClick={() => setPage('logs')}>查看全部 →</button></div><Logs rows={logs.slice(0, 7)}/></section><RegionStats regions={stats.regions}/></>}
        {page === 'logs' && <section className="panel"><div className="panel-head"><div><h2>查询活动</h2><p>最多显示最近 200 条</p></div><span className="pill">{logs.length} 条记录</span></div><Logs rows={logs}/></section>}
        {page === 'rules' && <><section className="panel"><div className="panel-head"><div><h2>规则列表</h2><p>本地记录优先，其次为过滤和条件转发</p></div><span className="pill">{rules.length} 条规则</span></div><div className="table-wrap"><table><thead><tr><th>类型</th><th>域名</th><th>记录 / 上游</th><th>TTL</th><th/></tr></thead><tbody>{rules.map(item => <tr key={item.id}><td><span className={`tag ${item.kind}`}>{kindName(item.kind)}</span></td><td className="strong">{item.domain}</td><td>{item.record_type ? `${item.record_type} · ${item.value}` : item.value || '—'}</td><td>{item.ttl || '—'}</td><td>{canEdit && <button className="text-button danger" onClick={() => run(() => api(`/rules/${item.id}`, token, { method: 'DELETE' }))}>删除</button>}</td></tr>)}{!rules.length && <Empty columns={5} text="暂无规则。添加记录或过滤规则开始使用。"/>}</tbody></table></div></section>{canEdit && <section className="panel form-panel"><div className="panel-head"><div><h2>新增规则</h2><p>变更后即时应用到新查询</p></div></div><form onSubmit={event => { event.preventDefault(); run(async () => { await api('/rules', token, { method: 'POST', body: JSON.stringify(rule) }); setRule({ kind: 'local', domain: '', record_type: 'A', value: '', ttl: 300 }) }) }} className="form-grid"><label>规则类型<select value={rule.kind} onChange={e => setRule({ ...rule, kind: e.target.value })}><option value="local">本地记录</option><option value="allow">白名单</option><option value="block">黑名单</option><option value="forward">条件转发</option></select></label><label>域名<input placeholder="example.com" value={rule.domain} onChange={e => setRule({ ...rule, domain: e.target.value })} required /></label>{rule.kind === 'local' && <label>记录类型<select value={rule.record_type} onChange={e => setRule({ ...rule, record_type: e.target.value })}><option>A</option><option>AAAA</option><option>CNAME</option><option>TXT</option></select></label>}{['local', 'forward'].includes(rule.kind) && <label>{rule.kind === 'forward' ? '上游地址' : '记录值'}<input placeholder={rule.kind === 'forward' ? '10.0.0.53:53' : '192.0.2.10'} value={rule.value} onChange={e => setRule({ ...rule, value: e.target.value })} required /></label>}{rule.kind === 'local' && <label>TTL（秒）<input type="number" min="1" max="86400" value={rule.ttl} onChange={e => setRule({ ...rule, ttl: Number(e.target.value) })}/></label>}<button className="btn primary" disabled={busy}>添加规则 →</button></form></section>}</>}
        {page === 'subscriptions' && <><section className="panel"><div className="panel-head"><div><h2>过滤订阅</h2><p>支持纯域名、hosts 和 Adblock 域名规则</p></div><span className="pill">{subscriptions.length} 个源</span></div><div className="subscription-list">{subscriptions.map(item => <div className="subscription" key={item.id}><div className="sub-icon">▤</div><div className="sub-main"><div className="strong truncate">{item.url}</div><small>{item.last_error ? `更新失败：${item.last_error}` : item.updated_at ? `最后更新 ${new Date(item.updated_at).toLocaleString()}` : '尚未更新'}</small></div>{canEdit && <div className="row-actions"><button className="btn tertiary" disabled={busy} onClick={() => run(() => api(`/subscriptions/${item.id}/refresh`, token, { method: 'POST' }))}>更新</button><button className="text-button danger" onClick={() => run(() => api(`/subscriptions/${item.id}`, token, { method: 'DELETE' }))}>删除</button></div>}</div>)}{!subscriptions.length && <div className="empty">暂无订阅源。</div>}</div></section>{canEdit && <section className="panel form-panel"><div className="panel-head"><div><h2>添加订阅源</h2><p>仅接受 HTTPS 地址；定时自动更新</p></div></div><form className="inline-form" onSubmit={event => { event.preventDefault(); run(async () => { await api('/subscriptions', token, { method: 'POST', body: JSON.stringify({ url }) }); setUrl('') }) }}><input type="url" placeholder="https://example.com/blocklist.txt" value={url} onChange={e => setUrl(e.target.value)} required/><button className="btn primary" disabled={busy}>添加订阅</button></form></section>}</>}
        {page === 'certificates' && <section className="panel certificate-panel"><div className="certificate-symbol">◇</div><span className="tag local">TLS CERTIFICATE</span><h2>安全连接证书</h2><p>DoH、DoT 和 DoQ 共用一组 PEM 证书。填写服务器上的绝对路径并保存；服务会先验证证书与私钥，再更新新连接使用的证书。替换同一路径下的文件后，使用重载按钮重新读取。</p>{isAdmin && <><form className="cert-path-form" onSubmit={event => { event.preventDefault(); run(() => api('/certificates', token, { method: 'PUT', body: JSON.stringify(certPaths) })) }}><label>证书链路径<input type="text" autoComplete="off" placeholder="/opt/rDns/certs/fullchain.pem" value={certPaths.certificate} onChange={e => setCertPaths({ ...certPaths, certificate: e.target.value })} required /></label><label>私钥路径<input type="text" autoComplete="off" placeholder="/opt/rDns/certs/privkey.pem" value={certPaths.private_key} onChange={e => setCertPaths({ ...certPaths, private_key: e.target.value })} required /></label><button className="btn primary" disabled={busy}>保存路径并应用</button></form><button className="btn tertiary" disabled={busy} onClick={() => run(() => api('/certificates/reload', token, { method: 'POST' }))}>↻ 重载当前路径</button></>}<div className="hint">只有管理员可配置路径和重载证书；操作结果会写入审计日志。</div></section>}
        {page === 'listeners' && <section className="panel"><div className="panel-head"><div><h2>协议监听</h2><p>保存后立即生效；端口冲突会阻止本次变更并显示错误</p></div><span className="pill">实时连接</span></div>{listenerDraft ? <form className="listener-form" onSubmit={event => { event.preventDefault(); run(saveListeners) }}>{[['dns_udp','DNS · UDP','53'],['dns_tcp','DNS · TCP','53'],['doh','DoH · HTTPS','443'],['dot','DoT · TLS','853'],['doq','DoQ · QUIC','853']].map(([key,label,port]) => <div className="listener-row" key={key}><div className="listener-name"><strong>{label}</strong><small>标准端口 {port}</small></div><label className="listener-switch"><input type="checkbox" checked={listenerDraft[key].enabled} disabled={!isAdmin} onChange={e => setListenerDraft({ ...listenerDraft, [key]: { ...listenerDraft[key], enabled: e.target.checked } })}/><span>{listenerDraft[key].enabled ? '启用' : '关闭'}</span></label><input className="listener-address" aria-label={`${label} 监听地址`} type="text" value={listenerDraft[key].address} disabled={!isAdmin} onChange={e => setListenerDraft({ ...listenerDraft, [key]: { ...listenerDraft[key], address: e.target.value } })}/><span className={`tag ${listenerStatus?.running?.[key] ? 'local' : 'forward'}`}>{listenerStatus?.running?.[key] ? '运行中' : '未监听'}</span></div>)}<div className="listener-actions"><span>管理面板始终监听本机，不受这些开关影响。</span>{isAdmin && <button className="btn primary" disabled={busy}>保存并应用</button>}</div></form> : <div className="empty">正在连接实时状态…</div>}</section>}
        {page === 'cache' && <section className="panel"><div className="panel-head"><div><h2>递归缓存</h2><p>权威 NS/Glue 和答案写入 SQLite，热点使用按字节限制的内存缓存</p></div><span className="pill">实时状态</span></div>{cacheStatus && cacheDraft ? <><div className="cache-metrics"><Metric title="进程内存 RSS" value={`${(cacheStatus.process_rss_bytes / 1048576).toFixed(1)} MiB`} foot="包含运行时和 DNS 缓存" icon="◉"/><Metric title="热点缓存" value={`${(cacheStatus.memory_bytes / 1048576).toFixed(1)} MiB`} foot={`${cacheStatus.memory_entries} 条 · 命中 ${cacheStatus.memory_hits} 次 · 预算 ${cacheDraft.memory_mib} MiB`} icon="▣"/><Metric title="SQLite 缓存" value={cacheStatus.disk_entries} foot={`${(cacheStatus.disk_bytes / 1048576).toFixed(1)} MiB · 命中 ${cacheStatus.disk_hits} 次`} icon="◈"/></div><form className="cache-form" onSubmit={event => { event.preventDefault(); run(saveCache) }}><label>热点内存预算（MiB）<input type="number" min="1" max="4096" value={cacheDraft.memory_mib} disabled={!isAdmin} onChange={e => setCacheDraft({ ...cacheDraft, memory_mib: Number(e.target.value) })}/></label><label>NS/Glue 最长缓存（秒）<input type="number" min="1" max="604800" value={cacheDraft.ns_max_ttl} disabled={!isAdmin} onChange={e => setCacheDraft({ ...cacheDraft, ns_max_ttl: Number(e.target.value) })}/></label><label>正向答案最长缓存（秒）<input type="number" min="1" max="604800" value={cacheDraft.answer_max_ttl} disabled={!isAdmin} onChange={e => setCacheDraft({ ...cacheDraft, answer_max_ttl: Number(e.target.value) })}/></label><label>负向答案最长缓存（秒）<input type="number" min="1" max="604800" value={cacheDraft.negative_max_ttl} disabled={!isAdmin} onChange={e => setCacheDraft({ ...cacheDraft, negative_max_ttl: Number(e.target.value) })}/></label><p>实际缓存时间不会超过权威 TTL；DNSSEC 签名提前到期时也会提前失效。更改上限会清空旧缓存并立即按新设置运行。</p>{isAdmin && <button className="btn primary" disabled={busy}>保存缓存设置</button>}</form></> : <div className="empty">正在连接实时状态…</div>}</section>}

        {page === 'portal' && isAdmin && <PortalAdmin token={token}/>}
        {page === 'accounts' && isAdmin && <><section className="panel"><div className="panel-head"><div><h2>账号列表</h2><p>当前组织的控制台成员</p></div><span className="pill">{accounts.length} 个账号</span></div><div className="table-wrap"><table><thead><tr><th>用户名</th><th>角色</th><th/></tr></thead><tbody>{accounts.map(item => <tr key={item.id}><td className="strong">{item.username}</td><td>{({ admin: '管理员', editor: '编辑者', viewer: '只读' })[item.role]}</td><td>{item.id !== me.id && <button className="text-button danger" onClick={() => run(() => api(`/accounts/${item.id}`, token, { method: 'DELETE' }))}>删除</button>}</td></tr>)}</tbody></table></div></section><section className="panel form-panel"><div className="panel-head"><div><h2>新增管理员账号</h2><p>管理员、编辑者和只读角色</p></div></div><form className="form-grid" onSubmit={event => { event.preventDefault(); run(async () => { await api('/accounts', token, { method: 'POST', body: JSON.stringify(account) }); setAccount({ username: '', password: '', role: 'viewer' }) }) }}><label>用户名<input value={account.username} minLength={3} onChange={e => setAccount({ ...account, username: e.target.value })} required/></label><label>密码<input type="password"  value={account.password} onChange={e => setAccount({ ...account, password: e.target.value })} required/></label><label>角色<select value={account.role} onChange={e => setAccount({ ...account, role: e.target.value })}><option value="viewer">只读</option><option value="editor">编辑者</option><option value="admin">管理员</option></select></label><button className="btn primary" disabled={busy}>创建账号 →</button></form></section><section className="panel"><div className="panel-head"><div><h2>操作审计</h2><p>最近 100 条管理操作</p></div></div><div className="table-wrap"><table><thead><tr><th>时间</th><th>操作人</th><th>操作</th><th>详情</th></tr></thead><tbody>{audit.map((item, i) => <tr key={`${item.at}-${i}`}><td>{new Date(item.at).toLocaleString()}</td><td className="strong">{item.actor}</td><td>{item.action}</td><td>{item.detail}</td></tr>)}{!audit.length && <Empty columns={4} text="暂无操作记录。"/>}</tbody></table></div></section></>}
      </main></div></div>
}

function subtitle(page) { return ({ portal: '管理注册、身份提供方、个人解析地址与查询统计。', overview: '实时掌握解析流量、过滤效果与服务状态。', logs: '查看客户端查询及策略处理结果。', rules: '定义本地域名、访问策略与条件转发。', subscriptions: '集中管理广告过滤列表。', listeners: '实时启停 DNS 协议并检查端口占用。', cache: '配置内存预算与 DNS TTL 上限。', clients: '配置来源网段和国家/地区、省级行政区的访问条件。', upstreams: '配置多上游轮询、代理连接与递归并行策略。', gfwlist: '按内置及订阅名单选择特定解析路径。', geoip: '维护离线数据库并检查来源 IP 的访问判断。', certificates: '更新加密 DNS 接入证书。', accounts: '管理控制台访问权限。' })[page] }
function kindName(kind) { return ({ local: '本地记录', allow: '白名单', block: '黑名单', forward: '条件转发' })[kind] || kind }
function Metric({ title, value, foot, icon }) { return <div className="metric"><div className="metric-top"><span>{title}</span><span className="metric-icon">{icon}</span></div><div className="metric-value">{value.toLocaleString?.() ?? value}</div><div className="metric-foot">{foot}</div></div> }
function Empty({ columns, text }) { return <tr><td colSpan={columns} className="empty">{text}</td></tr> }
function Logs({ rows }) { return <div className="table-wrap"><table><thead><tr><th>时间</th><th>查询域名</th><th>类型</th><th>客户端</th><th>来源地区</th><th>上游组</th><th>协议</th><th>结果</th><th>响应时间</th></tr></thead><tbody>{rows.map((row, i) => <tr key={`${row.at}-${i}`}><td>{new Date(row.at).toLocaleString()}</td><td className="strong">{row.domain}</td><td>{row.qtype}</td><td>{row.client}</td><td>{[row.country, row.province, row.city].filter(Boolean).join(' · ') || '未知'}</td><td>{row.upstream || '—'}</td><td>{row.protocol.toUpperCase()}</td><td><span className={`tag ${row.outcome === 'blocked' ? 'block' : row.outcome === 'error' ? 'error-tag' : 'local'}`}>{({ blocked: '已过滤', local: '本地', forward: '转发', recursive: '已解析', error: '错误', timeout: '超时', doh: 'DoH', gfw_doh: 'GFWList DoH', gfw_fallback_doh: 'GFWList 默认组兜底', client_whitelist: '网段未允许', client_blacklist: '网段已禁止', region_unknown: '未知地区拒绝', region_whitelist: '地区未允许', region_blacklist: '地区已禁止', dnssec_bogus: 'DNSSEC 验证失败' })[row.outcome] || row.outcome}</span></td><td>{row.duration_ms == null ? '—' : `${row.duration_ms.toFixed(2)} ms`}</td></tr>)}{!rows.length && <Empty columns={9} text="暂无查询记录。"/>}</tbody></table></div> }

createRoot(document.getElementById('root')).render(/^\/portal\/?$/.test(location.pathname) ? <Portal/> : <App />)
