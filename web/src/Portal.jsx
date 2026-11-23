import React, { useEffect, useState } from 'react'
import './portal.css'

async function request(path, { method = 'GET', body, token } = {}) {
  const response = await fetch(path, {
    method,
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

function Analytics({ token, users = [] }) {
  const [days, setDays] = useState(1),
    [page, setPage] = useState(1)
  const [user, setUser] = useState(''),
    [entry, setEntry] = useState('')
  const [revision, refresh] = useState(0),
    [data, setData] = useState(null),
    [error, setError] = useState('')
  useEffect(() => {
    let active = true
    setError('')
    setData(null)
    const params = new URLSearchParams({ days, page })
    if (user) params.set('user', user)
    if (entry) params.set('entry', entry)
    request((token ? adminAPI : memberAPI) + '/analytics?' + params, { token })
      .then((value) => {
        if (active) setData(value)
      })
      .catch((e) => {
        if (active) setError(e.message)
      })
    return () => {
      active = false
    }
  }, [days, page, user, entry, revision, token])
  const peak = Math.max(1, ...(data?.trend || []).map((row) => row.count))
  return (
    <section className="panel portal-section">
      <header className="panel-head">
        <div>
          <h2>查询分析</h2>
          {data && <p>日志保留 {data.retention} 天 · 趋势按 UTC 汇总</p>}
        </div>
        <button className="btn tertiary" onClick={() => refresh(revision + 1)}>
          刷新
        </button>
      </header>
      <div className="portal-filters">
        <label>
          时间范围
          <select
            value={days}
            onChange={(e) => {
              setDays(Number(e.target.value))
              setPage(1)
            }}
          >
            {[
              [1, '最近 24 小时'],
              [7, '最近 7 天'],
              [30, '最近 30 天'],
            ].map(([v, n]) => (
              <option key={v} value={v}>
                {n}
              </option>
            ))}
          </select>
        </label>
        {token && (
          <>
            <label>
              用户
              <select
                aria-label="用户筛选"
                value={user}
                onChange={(e) => {
                  setUser(e.target.value)
                  setPage(1)
                }}
              >
                <option value="">全部用户</option>
                {users.map((u) => (
                  <option value={u.id} key={u.id}>
                    {u.name} · #{u.id}
                  </option>
                ))}
              </select>
            </label>
            <label>
              入口
              <select
                value={entry}
                onChange={(e) => {
                  setEntry(e.target.value)
                  setPage(1)
                }}
              >
                <option value="">全部入口</option>
                {Object.entries(entries).map(([k, v]) => (
                  <option value={k} key={k}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
          </>
        )}
      </div>
      <ErrorMessage message={error} />
      {data && (
        <>
          <dl className="portal-metrics">
            {[
              ['查询量', data.total],
              ['拦截率', data.total ? ((100 * data.blocked) / data.total).toFixed(1) + '%' : '—'],
              ['平均耗时', data.latency == null ? '—' : data.latency.toFixed(1) + ' ms'],
            ].map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
          <div className="portal-breakdown">
            <div>
              <h3>查询趋势</h3>
              <div className="portal-series">
                {data.trend.map((r) => (
                  <div key={r.time}>
                    <time>{r.time.replace('T', ' ')}</time>
                    <meter min="0" max={peak} value={r.count} />
                    <b>{r.count}</b>
                  </div>
                ))}
                {!data.trend.length && '暂无查询'}
              </div>
            </div>
            <div>
              <h3>热门域名</h3>
              <Table labels={['域名', '查询量']} rows={data.domains.map((r) => [r.domain, r.count])} />
            </div>
          </div>
          <h3>查询明细</h3>
          <Table
            labels={['时间', '域名', '类型', '结果', '耗时', ...(token ? ['入口', '用户 ID'] : [])]}
            rows={data.logs.map((r) => [
              new Date(r.at).toLocaleString(),
              r.domain,
              r.qtype,
              r.outcome,
              r.duration_ms == null ? '—' : r.duration_ms.toFixed(1) + ' ms',
              ...(token ? [entries[r.entry] || r.entry, r.user] : []),
            ])}
          />
          <div className="portal-pagination">
            <button disabled={page === 1} onClick={() => setPage(page - 1)}>
              上一页
            </button>
            <span>第 {page} 页</span>
            <button disabled={page * 50 >= data.total} onClick={() => setPage(page + 1)}>
              下一页
            </button>
          </div>
        </>
      )}
    </section>
  )
}

export function Portal() {
  const [user, setUser] = useState(null),
    [options, setOptions] = useState(null),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false)
  const [signup, setSignup] = useState(false),
    [copied, setCopied] = useState(false)
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
  const address = user?.path ? (user.base || location.origin) + user.path : ''
  return (
    <main className="portal-shell">
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
          <form
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
          </form>
          {options.registration !== 'closed' && (
            <button
              className="text-button blue"
              onClick={() => {
                setSignup(!signup)
                setError('')
              }}
            >
              {signup ? '已有账号，去登录' : '注册新账号'}
            </button>
          )}
          {options.providers.map((p) => (
            <a className="btn tertiary" key={p.id} href={'/portal/auth/' + p.id}>
              使用 {p.label} 登录
            </a>
          ))}
        </section>
      ) : (
        <>
          <h1>{user.name} 的 DNS</h1>
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
              </>
            ) : (
              <>
                <p>账号待审核。管理员批准后即可获取地址。</p>
                <button className="btn tertiary" onClick={() => action(load)}>
                  刷新状态
                </button>
              </>
            )}
          </section>
          {address && <Analytics />}
        </>
      )}
    </main>
  )
}

const providerDefaults = {
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
      <legend>{provider.label || '身份提供方'}</legend>
      {base && provider.id && <p>登录回调地址 <code>{base.replace(/\/$/,'')}/portal/callback/{provider.id}</code></p>}
      <div className="portal-fields">
        <label>
          协议
          <select value={provider.kind} onChange={(e) => update({ kind: e.target.value })}>
            <option value="oidc">OpenID Connect</option>
            <option value="oauth">OAuth 2.0</option>
          </select>
        </label>
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
      </button>
    </fieldset>
  )
}
export function PortalAdmin({ token }) {
  const [cfg, setCfg] = useState(null),
    [users, setUsers] = useState([]),
    [error, setError] = useState(''),
    [notice, setNotice] = useState(''),
    [busy, setBusy] = useState(false)
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
  return (
    <div className="portal-admin">
      <ErrorMessage message={error} />
      {notice && (
        <p className="notice success" role="status">
          {notice}
        </p>
      )}
      {cfg && (
        <section className="panel">
          <header className="panel-head">
            <h2>注册与身份提供方</h2>
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
                <button
                  type="button"
                  className="btn tertiary"
                  onClick={() => setCfg({ ...cfg, providers: [...cfg.providers, { ...providerDefaults }] })}
                >
                  添加身份提供方
                </button>
                <button className="btn primary">保存并应用</button>
              </div>
            </fieldset>
          </form>
        </section>
      )}
      <section className="panel">
        <header className="panel-head">
          <h2>门户用户</h2>
          <button
            disabled={busy}
            className="btn tertiary"
            onClick={() => run(async () => setUsers(await req('/users')))}
          >
            刷新用户
          </button>
        </header>
        <Table
          labels={['用户 ID', '用户名', '登录方式', '状态', '操作']}
          rows={users.map((u) => [
            u.id,
            u.name,
            u.external ? '第三方' : '本地',
            states[u.status],
            <div className="portal-buttons">
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
            </div>,
          ])}
        />
      </section>
      <Analytics token={token} users={users} />
    </div>
  )
}
