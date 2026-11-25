import React, { useEffect, useRef, useState } from 'react'
import { DnsLookup, DnsRecords, QueryTrend, RecordTypeInput } from './PortalDns.jsx'
import { PortalDohGuide } from './PortalDohGuide.jsx'
import { PersonalDnsSettings } from './PortalDnsSettings.jsx'
import './portal.css'

async function request(path, { method = 'GET', body, token, signal } = {}) {
  const response = await fetch(path, {
    method,
    signal,
    cache: 'no-store',
    headers: {
      ...(body !== undefined && { 'Content-Type': 'application/json' }),
      ...(token && { Authorization: 'Bearer ' + token }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    const error = new Error((await response.text()) || '请求失败')
    error.status = response.status
    throw error
  }
  return response.json()
}

const memberAPI = '/portal/api'
const memberDnsRequest = (path, options) => request(memberAPI + path, options)
const adminAPI = '/api/v1/portal'
const states = { active: '已开通', pending: '待审核', disabled: '已停用' }
const entries = {
  personal: '个人 DoH',
  public: '公共 DoH',
  historical: '历史数据',
  udp: 'UDP',
  tcp: 'TCP',
  dot: 'DoT',
  doq: 'DoQ',
}
function ErrorMessage({ message }) {
  return (
    message && (
      <p role="alert" className="notice error">
        {message}
      </p>
    )
  )
}
function Table({ labels, rows, empty = '暂无数据' }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {labels.map((label) => (
              <th key={label} scope="col">
                {label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.map((cells, index) => (
              <tr key={index}>
                {cells.map((cell, i) => (
                  <td key={i}>{cell ?? '—'}</td>
                ))}
              </tr>
            ))
          ) : (
            <tr>
              <td className="empty" colSpan={labels.length}>
                {empty}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

const outcomes = {
  recursive: '递归', doh: 'DoH', gfw_doh: 'GFWList DoH', gfw_fallback_doh: 'GFWList 兜底',
  local: '本地记录', personal_local: '个人解析', forward: '条件转发', blocked: '已拦截', error: '错误', timeout: '超时', refused: '已拒绝',
  nxdomain: '域名不存在', nodata: '无记录', dnssec_bogus: 'DNSSEC 验证失败',
  recursive_dnssec_unverified: 'DNSSEC 验证失败，已返回递归结果',
  client_whitelist: '网段未允许', client_blacklist: '网段已禁止',
  region_unknown: '未知地区拒绝', region_whitelist: '地区未允许', region_blacklist: '地区已禁止',
}

function LogAnswer({ row, rcodes }) {
  if (!row.response) return row.rcode == null ? '未保存' : (rcodes[row.rcode] || 'RCODE' + row.rcode)
  const record = row.response.answers[0]
  const expand = record || row.response.authorities.length || row.response.additionals.length
  if (!expand) return <><span className="portal-rcode">{row.response.rcode}</span> <small>无记录</small></>
  return (
    <details className="portal-log-answer">
      <summary>
        <span className="portal-rcode">{row.response.rcode}</span>
        {record ? <code>{record.qtype} {record.data}</code> : <small>查看权威或附加记录</small>}
        {row.response.answers.length > 1 && <small>+{row.response.answers.length - 1}</small>}
      </summary>
      {row.response.ad && <small>DNSSEC 已验证</small>}
      <DnsRecords response={row.response} />
    </details>
  )
}

function Analytics({ token, users = [], lookupRevision = 0 }) {
  const [days, setDays] = useState(1)
  const [page, setPage] = useState(1)
  const [user, setUser] = useState('')
  const [entry, setEntry] = useState('')
  const [filters, setFilters] = useState('')
  const [revision, refresh] = useState(0)
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()
    setError('')
    setLoading(true)
    const params = new URLSearchParams(filters)
    params.set('days', days)
    params.set('page', page)
    if (user) params.set('user', user)
    if (entry) params.set('entry', entry)
    request((token ? adminAPI : memberAPI) + '/analytics?' + params, { token, signal: controller.signal })
      .then((value) => {
        if (!controller.signal.aborted) setData(value)
      })
      .catch((failure) => {
        if (!controller.signal.aborted) setError(failure.message)
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
  }, [days, page, user, entry, filters, revision, lookupRevision, token])

  function search(event) {
    event.preventDefault()
    const params = new URLSearchParams()
    for (const [key, value] of new FormData(event.currentTarget)) {
      if (value.trim()) params.set(key, value.trim())
    }
    setFilters(params.toString())
    setPage(1)
  }
  const labels = ['时间', '域名', '类型', '处理结果', '最终应答', '耗时', ...(token ? ['入口', '用户 ID'] : [])]
  return (
    <section className="panel portal-section portal-analytics" aria-busy={loading}>
      <header className="panel-head">
        <div>
          <h2>查询分析</h2>
          {data && <p>服务器时间（{data.server_offset}） · 日志保留 {data.retention} 天</p>}
        </div>
        <button className="btn tertiary" onClick={() => refresh((value) => value + 1)} disabled={loading}>刷新</button>
      </header>
      <div className="portal-filters portal-time-filters">
        <label>时间范围
          <select value={days} onChange={(e) => { setDays(Number(e.target.value)); setPage(1) }}>
            <option value={1}>最近 24 小时</option>
            <option value={7}>最近 7 天</option>
            <option value={30}>最近 30 天</option>
          </select>
        </label>
        {token && <>
          <label>用户
            <select aria-label="用户筛选" value={user} onChange={(e) => { setUser(e.target.value); setPage(1) }}>
              <option value="">全部用户</option>
              {users.map((u) => <option key={u.id} value={u.id}>{u.name} · #{u.id}</option>)}
            </select>
          </label>
          <label>入口
            <select value={entry} onChange={(e) => { setEntry(e.target.value); setPage(1) }}>
              <option value="">全部入口</option>
              {Object.entries(entries).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
            </select>
          </label>
        </>}
      </div>
      <ErrorMessage message={error} />
      {!data && loading && <p className="portal-loading" role="status">正在加载查询统计…</p>}
      {data && <>
        <dl className="portal-metrics">
          {[
            ['查询量', data.total.toLocaleString()],
            ['拦截率', data.total ? ((100 * data.blocked) / data.total).toFixed(1) + '%' : '—'],
            ['平均耗时', data.latency == null ? '—' : data.latency.toFixed(1) + ' ms'],
          ].map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}
        </dl>
        <div className="portal-breakdown">
          <QueryTrend rows={data.trend} hourly={days === 1} />
          <div className="portal-domains">
            <h3>热门域名</h3>
            <Table labels={['域名', '查询量']} rows={data.domains.map((row) => [row.domain, row.count.toLocaleString()])} />
          </div>
        </div>
        <div className="portal-log-heading"><h3>查询明细</h3><span>{data.detail_total.toLocaleString()} 条</span></div>
        <form className="portal-filters portal-log-filters" onSubmit={search}>
          <label>搜索域名<input name="search" type="search" maxLength={253} placeholder="输入域名关键词" /></label>
          <RecordTypeInput name="qtype" label="查询类型" placeholder="全部类型" />
          <label>处理结果
            <select name="outcome">
              <option value="">全部结果</option>
              {data.outcomes.map((key) => <option key={key} value={key}>{outcomes[key] || key}</option>)}
            </select>
          </label>
          <label>应答状态
            <select name="rcode">
              <option value="">全部状态</option>
              {Object.entries(data.rcodes).map(([code, label]) => <option key={code} value={code}>{label}</option>)}
            </select>
          </label>
          <button className="btn primary" disabled={loading}>筛选</button>
          {filters && <button type="button" className="btn tertiary" onClick={(event) => {
            event.currentTarget.form.reset()
            setFilters('')
            setPage(1)
          }}>清除</button>}
        </form>
        <div className="table-wrap portal-log-table">
          <table aria-label="查询明细">
            <thead><tr>{labels.map((label) => <th key={label} scope="col">{label}</th>)}</tr></thead>
            <tbody>{data.logs.length ? data.logs.map((row) => (
              <tr key={row.id}>
                <td data-label="时间"><time dateTime={row.at}>{row.local_at}</time></td>
                <td className="portal-log-domain" data-label="域名">{row.domain}</td>
                <td data-label="类型"><code>{row.qtype}</code></td>
                <td data-label="处理结果">{outcomes[row.outcome] || row.outcome}</td>
                <td data-label="最终应答"><LogAnswer row={row} rcodes={data.rcodes} /></td>
                <td data-label="耗时">{row.duration_ms == null ? '—' : row.duration_ms.toFixed(1) + ' ms'}</td>
                {token && <><td data-label="入口">{entries[row.entry] || row.entry}</td><td data-label="用户 ID">{row.user ?? '—'}</td></>}
              </tr>
            )) : <tr><td className="empty" colSpan={labels.length}>没有符合条件的查询</td></tr>}</tbody>
          </table>
        </div>
        <div className="portal-pagination">
          <button disabled={page === 1 || loading} onClick={() => setPage(page - 1)}>上一页</button>
          <span>第 {page} 页</span>
          <button disabled={page * 50 >= data.detail_total || loading} onClick={() => setPage(page + 1)}>下一页</button>
        </div>
      </>}
    </section>
  )
}

function EmailLogin({ busy, action, load }) {
  const [email, setEmail] = useState('')
  const [sent, setSent] = useState(false)
  const [code, setCode] = useState('')
  async function send() {
    await request(memberAPI + '/email/send', { method: 'POST', body: { email } })
    setCode('')
    setSent(true)
  }
  return (
    <form className="login-form" onSubmit={(e) => {
      e.preventDefault()
      action(sent ? async () => {
        await request(memberAPI + '/email/login', { method: 'POST', body: { email, code } })
        await load()
      } : send)
    }}>
      <label>登录邮箱<input type="email" required autoComplete="email" disabled={busy}
        value={email} onChange={(e) => { setEmail(e.target.value); setSent(false); setCode('') }} /></label>
      {sent && <>
        <p role="status">验证码已发送，10 分钟内有效。</p>
        <label>验证码<input required inputMode="numeric" autoComplete="one-time-code"
          pattern="[0-9]{8}" maxLength={8} value={code} onChange={(e) => setCode(e.target.value)} /></label>
        <button className="btn tertiary" type="button" disabled={busy} onClick={() => action(send)}>重新发送</button>
      </>}
      <button className="btn primary" disabled={busy}>{sent ? '使用验证码登录' : '发送邮箱验证码'}</button>
    </form>
  )
}

export function Portal() {
  const [user, setUser] = useState(null),
    [options, setOptions] = useState(null),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false)
  const [method, setMethod] = useState('password')
  const [copied, setCopied] = useState(false)
  const [iosQr, setIosQr] = useState(null)
  const [lookupRevision, refreshLookups] = useState(0)
  function showIosQr() {
    if (iosQr) setIosQr(null)
    else action(async () => setIosQr(await request(memberAPI + '/ios-qr', { method: 'POST' })))
  }
  async function load() {
    const [o, u] = await Promise.all([
      request(memberAPI + '/options'),
      request(memberAPI + '/me').catch((e) => {
        if (e.status === 401) return null
        throw e
      }),
    ])
    setOptions(o)
    setUser(u)
    setCopied(false)
    setIosQr(null)
  }
  useEffect(() => {
    document.title = 'rDns · 用户门户'
    load().catch((e) => setError(e.message))
  }, [])
  async function action(fn) {
    setError('')
    setBusy(true)
    try {
      await fn()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }
  const passwordEnabled = options?.password_login !== false
  const registerEnabled = passwordEnabled && options?.registration !== 'closed'
  const signup = method === 'register' && registerEnabled
  const emailSelected = options?.email && (method === 'email' || !passwordEnabled)
  function selectMethod(next) {
    setMethod(next)
    setError('')
  }
  const address = user?.resolver_url
  return (
    <main className={user ? "portal-shell portal-member" : "portal-shell"}>
      <header className="portal-brand">
        <div className="brand">
          <span className="brand-mark">r</span>Dns
        </div>
        <span>用户门户</span>
        {user && (
          <button
            className="btn tertiary"
            disabled={busy}
            onClick={() =>
              action(async () => {
                await request(memberAPI + '/logout', { method: 'POST', body: {} })
                await load()
              })
            }
          >
            退出登录
          </button>
        )}
      </header>
      <ErrorMessage message={error} />
      {!options ? (
        <p>正在加载门户…</p>
      ) : !user ? (
        <section className="panel portal-login">
          <h1>{signup ? '注册账户' : '登录用户门户'}</h1>
          <div className="portal-methods">
            {passwordEnabled && <button type="button" aria-pressed={!signup && !emailSelected} onClick={()=>selectMethod('password')}>账号登录</button>}
            {options.email && <button type="button" aria-pressed={Boolean(emailSelected)} onClick={()=>selectMethod('email')}>邮箱验证码登录</button>}
            {registerEnabled && <button type="button" aria-pressed={signup} onClick={()=>selectMethod('register')}>注册新账号</button>}
          </div>
          {passwordEnabled && !emailSelected && <form
            className="login-form"
            onSubmit={(e) => {
              e.preventDefault()
              const body = Object.fromEntries(new FormData(e.currentTarget))
              action(async () => {
                await request(memberAPI + (signup ? '/register' : '/login'), { method: 'POST', body })
                await load()
              })
            }}
          >
            <label>
              用户名
              <input name="username" required autoComplete="username" />
            </label>
            <label>
              密码
              <input
                name="password"
                required
                type="password"
                autoComplete={signup ? 'new-password' : 'current-password'}
              />
            </label>
            <button disabled={busy} className="btn primary">
              {signup ? '创建账户' : '登录'}
            </button>
          </form>}
          {!passwordEnabled && !options.email && options.providers.length === 0 && <p>管理员暂未启用门户登录方式。</p>}
          {emailSelected && <EmailLogin busy={busy} action={action} load={load} />}
          {options.providers.map((p) => (
            <a className="btn tertiary" key={p.id} href={'/portal/auth/' + p.id}>
              使用 {p.label} 登录
            </a>
          ))}
        </section>
      ) : (
        <>
          <h1 className="portal-member-title">{user.name} 的 DNS</h1>
          <div className="portal-workspace">
            <section className="panel portal-address">
              <h2>专属 DoH 地址</h2>
              {address ? (
                <>
                  <label>
                    解析器 URL
                    <input readOnly value={address} onFocus={(e) => e.target.select()} />
                  </label>
                  <div className="portal-buttons">
                    <button
                      className="btn primary"
                      onClick={() =>
                        action(async () => {
                          await navigator.clipboard.writeText(address)
                          setCopied(true)
                        })
                      }
                    >
                      {copied ? '已复制' : '复制地址'}
                    </button>
                    <button type="button" className="btn tertiary" disabled={busy} onClick={showIosQr}>
                      {iosQr ? '收起 iOS 二维码' : '扫码安装 iOS 描述文件'}
                    </button>
                    <button
                      disabled={busy}
                      className="btn tertiary"
                      onClick={() => {
                        if (confirm('更换后，使用旧地址的设备需要重新配置。继续更换？'))
                          action(async () => {
                            await request(memberAPI + '/rotate', { method: 'POST', body: {} })
                            await load()
                          })
                      }}
                    >
                      更换地址
                    </button>
                  </div>
                  {iosQr && <section className="ios-profile-qr" aria-label="iOS 描述文件二维码">
                    <img src={iosQr.image} width="240" height="240" alt="用 iPhone 相机扫描以下载 iOS 描述文件"/>
                    <div>
                      <h3>用 iPhone 相机扫码</h3>
                      <p>打开扫码链接并允许下载，然后前往「设置 → 已下载描述文件 → 安装」。</p>
                      <a href={iosQr.url} className="text-button blue">打开扫码下载链接</a>
                    </div>
                  </section>}
                </>
              ) : (
                <>
                  <p className="portal-hint">{user.path
                    ? '尚未配置 HTTPS DoH 入口。请从 HTTPS DoH 地址打开门户，或联系管理员配置公开地址。'
                    : '账号待审核。管理员批准后即可获取地址。'}</p>
                  <button className="btn tertiary" onClick={() => action(load)}>
                    刷新状态
                  </button>
                </>
              )}
            </section>
            {user.path && <DnsLookup key={user.path}
              run={(body) => request(memberAPI + '/lookup', { method: 'POST', body })}
              onComplete={() => refreshLookups((value) => value + 1)} />}
          </div>
          {user.path && <PersonalDnsSettings key={user.id} request={memberDnsRequest} />}
          {address && <PortalDohGuide />}
          {user.path && <Analytics lookupRevision={lookupRevision} />}
        </>
      )}
    </main>
  )
}

const providerDefaults = {
  enabled: true,
  id: '',
  label: '',
  kind: 'oidc',
  issuer: '',
  client_id: '',
  secret: '',
  authorization: '',
  token: '',
  profile: '',
  user_id: 'id',
  scope: '',
  auth_method: 'basic',
}
function MailSettings({ mail, update }) {
  return <fieldset>
    <legend>邮箱验证码</legend>
    <label className="portal-check"><input type="checkbox" checked={mail.enabled}
      onChange={(e) => update({ enabled: e.target.checked, port: mail.port || 465 })} />启用邮箱登录</label>
    {mail.enabled && <><div className="portal-fields"><label>允许登录的邮箱后缀<input required value={mail.domains || ''} placeholder="example.com" onChange={e=>update({domains:e.target.value})}/><small>填写域名，多个用逗号或空格分隔。只接受精确匹配的邮箱。</small></label></div>
      <details className="smtp-settings" open={!mail.host || undefined}><summary>SMTP 发信设置</summary><div className="portal-fields">
      <label>SMTP 加密方式<select value={mail.starttls ? 'starttls' : 'tls'}
        onChange={(e) => update({ starttls: e.target.value === 'starttls', port: e.target.value === 'starttls' ? 587 : 465 })}>
        <option value="tls">隐式 TLS</option><option value="starttls">STARTTLS</option>
      </select></label>
      {[
        ['host', 'SMTP 主机', 'text'], ['port', '端口', 'number'], ['sender', '发件邮箱', 'email'],
        ['username', 'SMTP 用户名', 'text'], ['password', 'SMTP 密码', 'password'],
      ].map(([key, label, type]) => <label key={key}>{label}
        <input type={type} value={mail[key] || ''} required={!['username','password'].includes(key)}
          placeholder={key === 'password' ? '已保存的密码留空沿用' : ''}
          onChange={(e) => update({ [key]: key === 'port' ? Number(e.target.value) : e.target.value })} />
      </label>)}
    </div></details></>}
  </fieldset>
}

function ProviderForm({ base, provider, update, remove }) {
  const fields = [
    ['id', '提供方 ID'],
    ['label', '显示名称'],
    ['client_id', 'Client ID'],
    ['secret', 'Client Secret'],
    ...(provider.kind === 'oidc'
      ? [['issuer', 'Issuer URL']]
      : [
          ['authorization', '授权端点'],
          ['token', '令牌端点'],
          ['profile', '用户资料端点'],
          ['user_id', '用户 ID 字段或 JSON Pointer'],
        ]),
    ['scope', 'Scopes（空格分隔）'],
  ]
  return (
    <fieldset className="portal-provider">
      <legend>{provider.kind === 'oidc' ? 'OpenID Connect' : 'OAuth 2.0'}{provider.label && ' · '+provider.label}</legend>
      <label className="portal-check"><input type="checkbox" checked={provider.enabled} onChange={e=>update({enabled:e.target.checked})}/>允许通过此提供方登录</label>
      <details open={!provider.id || undefined}><summary>提供方连接设置</summary>
      {base && provider.id && <p>登录回调地址 <code>{base.replace(/\/$/,'')}/portal/callback/{provider.id}</code></p>}
      <div className="portal-fields">
        {fields.map(([k, label]) => (
          <label key={k}>
            {label}
            <input
              type={k === 'secret' ? 'password' : 'text'}
              value={provider[k] || ''}
              autoComplete="off"
              placeholder={k === 'secret' ? '已保存的密钥留空沿用' : ''}
              required={!['scope', 'secret'].includes(k)}
              onChange={(e) => update({ [k]: e.target.value })}
            />
          </label>
        ))}
        <label>
          客户端认证
          <select
            value={provider.auth_method || 'basic'}
            onChange={(e) => update({ auth_method: e.target.value })}
          >
            <option value="basic">HTTP Basic</option>
            <option value="body">请求体</option>
          </select>
        </label>
      </div>
      <button type="button" className="text-button danger" onClick={remove}>
        移除此提供方
      </button></details>
    </fieldset>
  )
}
function loginMethodLabel(user) {
  if (user.email_login) return '邮箱验证码'
  return user.external ? '第三方' : '本地'
}
export function PortalAdmin({ token }) {
  const [cfg, setCfg] = useState(null),
    [users, setUsers] = useState([]),
    [error, setError] = useState(''),
    [notice, setNotice] = useState(''),
    [busy, setBusy] = useState(false)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('')
  const [editor, setEditor] = useState(null)
  const nameInput = useRef(null)
  useEffect(() => {
    if (editor) nameInput.current?.focus()
  }, [editor])
  const [userPage, setUserPage] = useState(1)
  const term = search.trim().toLowerCase()
  const matches = users.filter(user => (!filter || user.status === filter)
    && (!term || user.name.toLowerCase().includes(term) || String(user.id) === term))
  const pageSize = 25
  const pages = Math.max(1, Math.ceil(matches.length / pageSize))
  const currentPage = Math.min(userPage, pages)
  const visibleUsers = matches.slice((currentPage - 1) * pageSize, currentPage * pageSize)
  const req = (path, opts = {}) => request(adminAPI + path, { ...opts, token })
  useEffect(() => {
    Promise.all([req('/settings'), req('/users')])
      .then(([c, u]) => {
        setCfg(c)
        setUsers(u)
      })
      .catch((e) => setError(e.message))
  }, [token])
  async function run(fn) {
    setBusy(true)
    setNotice('')
    setError('')
    try {
      await fn()
      setNotice('已应用')
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }
  function changeUser(u, action) {
    if (!confirm('确定对 ' + u.name + ' 执行此操作？')) return
    run(async () => {
      await req('/users/' + u.id, { method: 'POST', body: { action } })
      setUsers(await req('/users'))
    })
  }
  function saveUser(event) {
    event.preventDefault()
    const { username, password } = Object.fromEntries(new FormData(event.currentTarget))
    run(async () => {
      await req(editor.id ? '/users/' + editor.id : '/users', {
        method: editor.id ? 'PUT' : 'POST',
        body: { username, ...(password ? { password } : {}) },
      })
      setEditor(null)
      setUsers(await req('/users'))
    })
  }

  function removeUser(user) {
    if (!confirm(`删除「${user.name}」？该用户的登录会话和个人 DoH 地址将立即失效。历史查询记录按现有保留周期处理。`)) return
    run(async () => {
      await req('/users/' + user.id, { method: 'DELETE' })
      setEditor(current => current?.id === user.id ? null : current)
      setUsers(await req('/users'))
    })
  }

  return (
    <div className="portal-admin">
      <ErrorMessage message={error} />
      {notice && (
        <p className="notice success" role="status">
          {notice}
        </p>
      )}
      <section className="panel portal-user-list">
        <header className="panel-head">
          <h2>门户用户</h2>
          <div className="portal-buttons portal-user-actions">
            <button type="button" disabled={busy} className="btn tertiary" onClick={() => run(async () => setUsers(await req('/users')))}>刷新用户</button>
            <button type="button" disabled={busy} className="btn primary" onClick={() => setEditor({})}>新增用户</button>
          </div>
        </header>
        {editor && <form key={editor.id ?? 'new'} className="portal-user-editor" onSubmit={saveUser}>
          <h3>{editor.id ? `编辑用户 · ${editor.name}` : '新增门户用户'}</h3>
          <fieldset className="portal-fields" disabled={busy}>
            <label>{editor.external ? '显示名称' : '用户名'}<input ref={nameInput} name="username" defaultValue={editor.name ?? ''} minLength={3} maxLength={128} required autoComplete="off"/></label>
            {!editor.external && <label>{editor.id ? '新密码（可选）' : '初始密码'}<input name="password" type="password" maxLength={1024} required={!editor.id} autoComplete="new-password"/></label>}
          </fieldset>
          {editor.id && !editor.external && <p>留空沿用当前密码。重设密码后，用户需重新登录门户。</p>}
          <div className="portal-buttons">
            <button disabled={busy} className="btn primary">{editor.id ? '保存修改' : '创建用户'}</button>
            <button type="button" disabled={busy} className="btn tertiary" onClick={()=>setEditor(null)}>取消</button>
          </div>
        </form>}
        <div className="portal-filters portal-user-toolbar">
          <label>查找用户<input type="search" value={search} placeholder="输入用户名或用户 ID" onChange={e=>{setSearch(e.target.value);setUserPage(1)}}/></label>
          <label>状态<select value={filter} onChange={e=>{setFilter(e.target.value);setUserPage(1)}}>
            <option value="">全部状态</option>
            {Object.entries(states).map(([key,name])=><option key={key} value={key}>{name}</option>)}
          </select></label>
          <span className="muted" role="status">{matches.length} 位用户</span>
        </div>
        <Table
          labels={['用户 ID', '用户名', '登录方式', '状态', '操作']}
          empty={term || filter ? '没有符合条件的用户' : '暂无门户用户'}
          rows={visibleUsers.map((u) => [
            u.id,
            <div className="portal-user-name"><span>{u.name}</span><small>#{u.id} · {loginMethodLabel(u)}</small></div>,
            loginMethodLabel(u),
            states[u.status],
            <div className="portal-buttons portal-user-actions">
              <button type="button" className="text-button blue" disabled={busy} onClick={()=>setEditor(u)}>编辑</button>
              {(u.status === 'active'
                ? [
                    ['rotate', '重置地址'],
                    ['disable', '停用'],
                  ]
                : u.status === 'pending'
                  ? [
                      ['activate', '批准'],
                      ['disable', '停用'],
                    ]
                  : [['activate', '重新开通']]
              ).map(([k, label]) => (
                <button key={k} disabled={busy} className="text-button blue" onClick={() => changeUser(u, k)}>
                  {label}
                </button>
              ))}
              <button type="button" className="text-button danger" disabled={busy} onClick={()=>removeUser(u)}>删除</button>
            </div>,
          ])}
        />
        {pages > 1 && <nav className="portal-pagination" aria-label="门户用户分页">
          <button type="button" disabled={currentPage===1} onClick={()=>setUserPage(currentPage-1)}>上一页</button>
          <span>{currentPage} / {pages} 页</span>
          <button type="button" disabled={currentPage===pages} onClick={()=>setUserPage(currentPage+1)}>下一页</button>
        </nav>}
      </section>
      {cfg && (
        <section className="panel">
          <header className="panel-head">
            <h2>门户注册与登录</h2>
          </header>
          <form
            className="portal-settings"
            onSubmit={(e) => {
              e.preventDefault()
              run(async () => {
                await req('/settings', { method: 'PUT', body: cfg })
                setCfg(await req('/settings'))
              })
            }}
          >
            <fieldset disabled={busy}>
              <section className="portal-config-block"><h3>注册与访问</h3>
              <div className="portal-fields">
                <label>
                  注册策略
                  <select
                    value={cfg.registration}
                    onChange={(e) => setCfg({ ...cfg, registration: e.target.value })}
                  >
                    <option value="open">开放注册</option>
                    <option value="approval">需管理员审核</option>
                    <option value="closed">关闭注册</option>
                  </select>
                </label>
                <label>
                  对外 HTTPS 地址
                  <input
                    type="url"
                    placeholder="https://dns.example.com"
                    value={cfg.base}
                    onChange={(e) => setCfg({ ...cfg, base: e.target.value })}
                  />
                </label>
              </div>
              <label className="portal-check">
                <input
                  type="checkbox"
                  checked={cfg.public}
                  onChange={(e) => setCfg({ ...cfg, public: e.target.checked })}
                />
                启用公共 /dns-query
              </label>
              </section>
              <section className="portal-config-block"><h3>允许的登录方式</h3>
              <label className="portal-check"><input type="checkbox" checked={cfg.password_login} onChange={e=>setCfg({...cfg,password_login:e.target.checked})}/>账号密码登录与注册</label>
              {cfg.email && <MailSettings mail={cfg.email} update={(changes) => setCfg({ ...cfg, email: { ...cfg.email, ...changes } })} />}
              {cfg.providers.map((p, i) => (
                <ProviderForm
                  key={i}
                  provider={p}
                  base={cfg.base}
                  update={(changes) =>
                    setCfg({
                      ...cfg,
                      providers: cfg.providers.map((v, j) => (j === i ? { ...v, ...changes } : v)),
                    })
                  }
                  remove={() => setCfg({ ...cfg, providers: cfg.providers.filter((_, j) => j !== i) })}
                />
              ))}
              <div className="portal-buttons">
                {['oauth','oidc'].map(kind=><button key={kind} type="button" className="btn tertiary"
                  onClick={()=>setCfg({...cfg,providers:[...cfg.providers,{...providerDefaults,kind}]})}>
                  {kind==='oauth'?'添加 OAuth 2.0':'添加 OpenID Connect'}
                </button>)}
              </div></section>
              <div className="portal-buttons">
                <button className="btn primary">保存并应用</button>
              </div>
            </fieldset>
          </form>
        </section>
      )}
      <Analytics token={token} users={users} />
    </div>
  )
}
