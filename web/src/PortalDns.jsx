import React, { useEffect, useId, useRef, useState } from 'react'

const recordTypes = [
  'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA',
  'HTTPS', 'SVCB', 'NAPTR', 'TLSA', 'SSHFP', 'DNSKEY', 'DS', 'RRSIG',
  'NSEC', 'NSEC3', 'DNAME', 'URI', 'LOC', 'ANY',
]

// IANA DNS RR TYPE registry, plus Hickory's ANAME type.
const namedTypes = {
  1: 'A', 2: 'NS', 3: 'MD', 4: 'MF', 5: 'CNAME', 6: 'SOA', 7: 'MB', 8: 'MG', 9: 'MR',
  10: 'NULL', 11: 'WKS', 12: 'PTR', 13: 'HINFO', 14: 'MINFO', 15: 'MX', 16: 'TXT',
  17: 'RP', 18: 'AFSDB', 19: 'X25', 20: 'ISDN', 21: 'RT', 22: 'NSAP', 23: 'NSAP-PTR',
  24: 'SIG', 25: 'KEY', 26: 'PX', 27: 'GPOS', 28: 'AAAA', 29: 'LOC', 30: 'NXT',
  31: 'EID', 32: 'NIMLOC', 33: 'SRV', 34: 'ATMA', 35: 'NAPTR', 36: 'KX', 37: 'CERT',
  38: 'A6', 39: 'DNAME', 40: 'SINK', 41: 'OPT', 42: 'APL', 43: 'DS', 44: 'SSHFP',
  45: 'IPSECKEY', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 49: 'DHCID', 50: 'NSEC3',
  51: 'NSEC3PARAM', 52: 'TLSA', 53: 'SMIMEA', 54: 'DELEGPARAM', 55: 'HIP',
  56: 'NINFO', 57: 'RKEY', 58: 'TALINK', 59: 'CDS', 60: 'CDNSKEY', 61: 'OPENPGPKEY',
  62: 'CSYNC', 63: 'ZONEMD', 64: 'SVCB', 65: 'HTTPS', 66: 'DSYNC', 67: 'HHIT', 68: 'BRID',
  69: 'UNECE', 70: 'ISO', 99: 'SPF', 100: 'UINFO', 101: 'UID', 102: 'GID', 103: 'UNSPEC',
  104: 'NID', 105: 'L32', 106: 'L64', 107: 'LP', 108: 'EUI48', 109: 'EUI64', 128: 'NXNAME',
  249: 'TKEY', 250: 'TSIG', 251: 'IXFR', 252: 'AXFR', 253: 'MAILB', 254: 'MAILA', 255: 'ANY',
  256: 'URI', 257: 'CAA', 258: 'AVC', 259: 'DOA', 260: 'AMTRELAY', 261: 'RESINFO',
  262: 'WALLET', 263: 'CLA', 264: 'IPN', 32768: 'TA', 32769: 'DLV', 61440: 'DELEG', 65305: 'ANAME',
}
const commonCodes = [1, 28, 5, 15, 16, 2, 6, 12, 33, 257, 65, 64]
const otherCodes = Object.keys(namedTypes).map(Number).filter((code) => !commonCodes.includes(code))
  .sort((first, second) => namedTypes[first].localeCompare(namedTypes[second], 'en'))
const byteValues = Array.from({ length: 256 }, (_, index) => index)

function LookupTypeOptions({ value, onChange, disabled }) {
  const [range, setRange] = useState(65280)
  return (
    <>
      <label>
        记录类型
        <select name="qtype" value={value} onChange={(event) => onChange(event.target.value)} disabled={disabled}>
          <optgroup label="常用">
            {commonCodes.map((code) => <option key={code} value={code}>{namedTypes[code]}</option>)}
          </optgroup>
          <optgroup label="其他类型">
            {otherCodes.map((code) => <option key={code} value={code}>{namedTypes[code]}</option>)}
          </optgroup>
          <option value="custom">按类型码选择</option>
        </select>
      </label>
      {value === 'custom' && (
        <div className="portal-type-code">
          <label>
            类型码范围
            <select value={range} onChange={(event) => setRange(Number(event.target.value))} disabled={disabled}>
              {byteValues.map((index) => {
                const start = index * 256
                return <option key={start} value={start}>{start}–{start + 255}</option>
              })}
            </select>
          </label>
          <label>
            类型码
            <select key={range} name="qtype_code" disabled={disabled}>
              {byteValues.map((offset) => {
                const code = range + offset
                return <option key={code} value={code}>TYPE{code}</option>
              })}
            </select>
          </label>
        </div>
      )}
    </>
  )
}

export function RecordTypeInput({ name, label, defaultValue = '', placeholder, required }) {
  const id = useId()
  return (
    <label>
      {label}
      <input name={name} list={id} defaultValue={defaultValue} placeholder={placeholder}
        required={required} autoComplete="off" spellCheck="false" maxLength={16} />
      <datalist id={id}>{recordTypes.map((type) => <option key={type} value={type} />)}</datalist>
    </label>
  )
}

export function DnsRecords({ response }) {
  return [
    ['应答', response.answers],
    ['权威', response.authorities],
    ['附加', response.additionals],
  ].filter(([, records]) => records.length).map(([label, records]) => (
    <div key={label} className="dns-record-group">
      <h4>{label} <span>{records.length}</span></h4>
      <ul>
        {records.map((row, index) => (
          <li key={index}>
            <div><b>{row.qtype}</b> <span>{row.name}</span> <small>TTL {row.ttl}s</small></div>
            <code>{row.data}</code>
          </li>
        ))}
      </ul>
    </div>
  ))
}

export function DnsLookup({ run, onComplete }) {
  const [answer, setAnswer] = useState(null)
  const [queryType, setQueryType] = useState('1')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit(event) {
    event.preventDefault()
    if (busy) return
    const data = new FormData(event.currentTarget)
    const selectedCode = Number(queryType === 'custom' ? data.get('qtype_code') : queryType)
    setBusy(true)
    setAnswer(null)
    setError('')
    try {
      const result = await run({ domain: data.get('domain'), qtype: 'TYPE' + selectedCode, dnssec_ok: data.has('dnssec') })
      setAnswer({ ...result, qtype: namedTypes[selectedCode] || result.qtype })
      onComplete()
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="panel portal-lookup">
      <h2>DNS 解析测试</h2>
      <form className="portal-lookup-form" onSubmit={submit}>
        <label>
          域名
          <input name="domain" placeholder="example.com" required maxLength={253}
            autoComplete="off" autoCapitalize="none" spellCheck="false" />
        </label>
        <LookupTypeOptions value={queryType} onChange={setQueryType} disabled={busy} />
        <label className="portal-dnssec"><input type="checkbox" name="dnssec" /> 请求 DNSSEC 记录</label>
        <button className="btn primary" disabled={busy}>{busy ? '正在查询…' : '开始查询'}</button>
      </form>
      {error && <p role="alert" className="notice error">{error}</p>}
      {answer && (
        <div className="portal-lookup-result">
          <div role="status" className="portal-result-head">
            <strong>{answer.domain} <small>{answer.qtype}</small></strong>
            <span className="portal-rcode">{answer.response.rcode}</span>
            <span>{answer.duration_ms.toFixed(1)} ms</span>
            {answer.response.ad && <span>DNSSEC 已验证</span>}
          </div>
          {!answer.response.answers.length && <p className="portal-hint">应答区无记录</p>}
          <DnsRecords response={answer.response} />
        </div>
      )}
    </section>
  )
}

const plot = { left: 40, right: 12, top: 10, bottom: 28 }

export function QueryTrend({ rows, hourly }) {
  const canvas = useRef(null)
  const [active, setActive] = useState(null)
  const selected = active == null ? null : rows[Math.min(active, rows.length - 1)]
  useEffect(() => {
    const element = canvas.current
    const context = element.getContext('2d')
    if (!context) return
    function draw() {
      const width = element.clientWidth
      const height = element.clientHeight
      if (!width || !height) return
      const ratio = window.devicePixelRatio || 1
      element.width = Math.round(width * ratio)
      element.height = Math.round(height * ratio)
      context.scale(ratio, ratio)
      const end = height - plot.bottom
      const range = Math.max(1, width - plot.left - plot.right)
      const indexRange = Math.max(1, rows.length - 1)
      const step = Math.max(1, Math.ceil(Math.max(0, ...rows.map((row) => row.count)) / 4))
      const x = (i) => plot.left + range * i / indexRange
      const y = (n) => end - (end - plot.top) * n / (step * 4)
      context.font = '11px ui-monospace, monospace'
      const theme = getComputedStyle(element)
      const color = (token) => theme.getPropertyValue('--portal-' + token).trim()
      context.fillStyle = color('muted')
      context.strokeStyle = color('edge')
      context.textAlign = 'right'
      context.textBaseline = 'middle'
      for (let tick = 0; tick <= 4; tick++) {
        const value = tick * step
        context.beginPath()
        context.moveTo(plot.left, y(value))
        context.lineTo(width - plot.right, y(value))
        context.stroke()
        context.fillText(value.toLocaleString(), plot.left - 6, y(value))
      }
      const marks = Math.min(rows.length, width < 380 ? 3 : 5)
      for (let mark = 0; mark < marks; mark++) {
        const index = Math.round((rows.length - 1) * mark / Math.max(1, marks - 1))
        context.textAlign = mark === 0 ? 'left' : mark === marks - 1 ? 'right' : 'center'
        const time = rows[index].time
        const edge = mark === 0 || mark === marks - 1
        const label = hourly ? (edge ? time.slice(5).replace('T', ' ') : time.slice(11)) : time.slice(5)
        context.fillText(label, x(index), end + 15)
      }
      if (!rows.length) return
      const area = context.createLinearGradient(0, plot.top, 0, end)
      area.addColorStop(0, color('secondary') + '40')
      area.addColorStop(1, color('secondary') + '08')
      function line() {
        context.moveTo(x(0), y(rows[0].count))
        rows.slice(1).forEach((row, index) => context.lineTo(x(index + 1), y(row.count)))
      }
      context.beginPath()
      line()
      context.lineTo(x(rows.length - 1), end)
      context.lineTo(x(0), end)
      context.closePath()
      context.fillStyle = area
      context.fill()
      context.beginPath()
      line()
      context.lineWidth = 2
      context.lineJoin = 'round'
      context.strokeStyle = color('secondary')
      context.stroke()
      if (selected) {
        const index = rows.indexOf(selected)
        context.beginPath()
        context.arc(x(index), y(selected.count), 4, 0, Math.PI * 2)
        context.fillStyle = color('ink')
        context.fill()
      }
    }
    const observer = new ResizeObserver(draw)
    observer.observe(element)
    draw()
    return () => observer.disconnect()
  }, [rows, hourly, selected])
  return (
    <div className="portal-chart">
      <div className="portal-chart-caption">
        <h3>查询趋势</h3>
        <span>{selected ? selected.time.replace('T', ' ') + ' · ' + selected.count.toLocaleString() + ' 次' : hourly ? '每小时' : '每日'}</span>
      </div>
      <canvas ref={canvas} tabIndex={rows.length ? 0 : undefined}
        aria-label={selected ? selected.time.replace('T', ' ') + '，' + selected.count + ' 次查询' : '查询趋势折线图，使用左右方向键查看数据'}
        onKeyDown={(event) => {
          if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return
          event.preventDefault()
          const next = (active ?? (event.key === 'ArrowLeft' ? rows.length : -1)) + (event.key === 'ArrowLeft' ? -1 : 1)
          setActive(Math.max(0, Math.min(next, rows.length - 1)))
        }}
        onPointerMove={(event) => {
          const box = event.currentTarget.getBoundingClientRect()
          const fraction = (event.clientX - box.left - plot.left) / Math.max(1, box.width - plot.left - plot.right)
          setActive(Math.max(0, Math.min(rows.length - 1, Math.round(fraction * (rows.length - 1)))))
        }}
        onPointerLeave={() => setActive(null)}
        onBlur={() => setActive(null)}>
        {rows.map((row) => row.time + ' ' + row.count + ' 次').join('，')}
      </canvas>
    </div>
  )
}
