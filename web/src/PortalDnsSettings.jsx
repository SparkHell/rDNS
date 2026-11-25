import React, { useEffect, useRef, useState } from 'react'

const switches = [
  { name: 'adguard', label: 'AdGuard 广告过滤', detail: '拦截管理员维护的名单中的广告和跟踪域名。' },
  { name: 'gfwlist', label: 'GFWList 分流', detail: '匹配的域名使用管理员配置的 DoH 上游。' },
]

const recordValues = {
  A: ['IPv4 地址', '192.0.2.10'],
  AAAA: ['IPv6 地址', '2001:db8::10'],
  CNAME: ['目标域名', 'target.example.com'],
  TXT: ['文本内容', '最多 255 字节'],
}

function RecordEditor({ record, busy, onSave, onCancel }) {
  const [kind, setKind] = useState(record?.record_type || 'A')
  const domainInput = useRef(null)
  useEffect(() => { domainInput.current?.focus() }, [])
  const [valueLabel, valueHint] = recordValues[kind]
  return <form className="form-grid portal-personal-record-form" onSubmit={(event) => {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    onSave({ domain: fields.get('domain'), record_type: kind, value: fields.get('value'), ttl: Number(fields.get('ttl')) })
  }}>
    <label>记录域名<input name="domain" ref={domainInput} defaultValue={record?.domain} disabled={busy}
      maxLength={254} placeholder="host.example.com" autoComplete="off" spellCheck={false} required /></label>
    <label>记录类型<select value={kind} onChange={(event) => setKind(event.target.value)} disabled={busy}>
      {Object.keys(recordValues).map((type) => <option key={type}>{type}</option>)}
    </select></label>
    <label>{valueLabel}<input name="value" defaultValue={record?.value} disabled={busy} maxLength={255}
      placeholder={valueHint} autoComplete="off" spellCheck={false} required={kind !== 'TXT'} /></label>
    <label>TTL（秒）<input name="ttl" type="number" min={1} max={86400} defaultValue={record?.ttl ?? 300} disabled={busy} required /></label>
    <div className="portal-buttons">
      <button className="btn primary" disabled={busy}>保存记录</button>
      <button className="btn tertiary" type="button" disabled={busy} onClick={onCancel}>取消</button>
    </div>
  </form>
}

export function PersonalDnsSettings({ request }) {
  const [data, setData] = useState(null)
  const [draft, setDraft] = useState(null)
  const [editing, setEditing] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [status, setStatus] = useState('')
  const [reload, setReload] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    request('/dns-settings', { signal: controller.signal }).then((result) => {
      setData(result)
      setDraft(result.preferences)
    }).catch((error) => {
      if (!controller.signal.aborted) setError(error.message)
    })
    return () => controller.abort()
  }, [request, reload])

  async function save(task, message) {
    setBusy(true)
    setError('')
    setStatus('')
    try {
      await task()
      setStatus(message)
    } catch (error) {
      setError(error.message)
    } finally {
      setBusy(false)
    }
  }

  function saveRecord(input) {
    const id = editing.id
    save(async () => {
      const record = await request(id ? `/dns-records/${id}` : '/dns-records', { method: id ? 'PUT' : 'POST', body: input })
      setData((current) => ({ ...current, records: [...current.records.filter((row) => row.id !== record.id), record]
        .sort((a, b) => a.domain.localeCompare(b.domain) || a.record_type.localeCompare(b.record_type) || a.id - b.id) }))
      setEditing(null)
    }, '解析记录已保存')
  }

  function deleteRecord(record) {
    if (!confirm(`删除 ${record.domain} 的 ${record.record_type} 记录？`)) return
    save(async () => {
      await request(`/dns-records/${record.id}`, { method: 'DELETE' })
      setData((current) => ({ ...current, records: current.records.filter((row) => row.id !== record.id) }))
      if (editing?.id === record.id) setEditing(null)
    }, '解析记录已删除')
  }

  return <section className="panel portal-personal-dns" aria-labelledby="portal-personal-dns-title">
    <h2 id="portal-personal-dns-title">个人 DNS 设置</h2>
    <p className="portal-hint">仅影响你的专属 DoH 地址和本页的 DNS 解析测试。客户端可能会继续使用缓存的旧结果，直到 TTL 到期。</p>
    {error && <p className="notice error" role="alert">{error}</p>}
    {!data ? (error
      ? <button className="btn tertiary" onClick={() => { setError(''); setReload((value) => value + 1) }}>重新加载设置</button>
      : <p className="portal-hint" role="status">正在加载个人 DNS 设置…</p>) : <>
      <form className="portal-personal-switches" onSubmit={(event) => {
        event.preventDefault()
        save(async () => {
          const preferences = await request('/dns-settings', { method: 'PUT', body: draft })
          setData((current) => ({ ...current, preferences }))
          setDraft(preferences)
        }, '规则开关已保存')
      }}>
        <h3>规则开关</h3>
        <div className="portal-personal-switch-list">
          {switches.map(({ name, label, detail }) => <div key={name}>
            <label><input type="checkbox" checked={draft[name]} disabled={busy}
              aria-describedby={`personal-${name}-detail`}
              onChange={(event) => setDraft({ ...draft, [name]: event.target.checked })} />{label}</label>
            <p className="portal-hint" id={`personal-${name}-detail`}>{detail}
              {!data.available[name] && ' 管理员尚未开放，保存后将等开放时生效。'}</p>
          </div>)}
        </div>
        <button className="btn primary" disabled={busy || switches.every(({ name }) => draft[name] === data.preferences[name])}>保存开关</button>
      </form>
      <section className="portal-personal-records" aria-labelledby="portal-personal-records-title">
        <div className="portal-personal-record-heading">
          <div><h3 id="portal-personal-records-title">自定义解析</h3>
            <p className="portal-hint">支持 A、AAAA、CNAME 和 TXT，仅匹配填写的域名。若该域名有个人记录但缺少所请求的类型，会返回空应答。</p></div>
          <button className="btn tertiary" type="button" disabled={busy || editing !== null}
            onClick={() => { setError(''); setStatus(''); setEditing({}) }}>添加记录</button>
        </div>
        {editing && <RecordEditor key={editing.id ?? 'new'} record={editing} busy={busy} onSave={saveRecord}
          onCancel={() => { setEditing(null); setError('') }} />}
        {data.records.length ? <ul className="portal-personal-record-list">
          {data.records.map((record) => <li key={record.id}>
            <div className="portal-personal-record-data">
              <strong>{record.domain}</strong>
              <span>{record.record_type} · TTL {record.ttl} 秒</span>
              <code>{record.value || '（空文本）'}</code>
            </div>
            <div className="portal-buttons">
              <button className="btn tertiary" type="button" disabled={busy || editing !== null}
                aria-label={`编辑 ${record.domain} ${record.record_type}`} onClick={() => { setError(''); setStatus(''); setEditing(record) }}>编辑</button>
              <button className="text-button danger" type="button" disabled={busy}
                aria-label={`删除 ${record.domain} ${record.record_type}`} onClick={() => deleteRecord(record)}>删除</button>
            </div>
          </li>)}
        </ul> : <p className="portal-hint">暂无自定义解析记录。</p>}
      </section>
      <p className="portal-personal-status" role="status">{status}</p>
    </>}
  </section>
}
