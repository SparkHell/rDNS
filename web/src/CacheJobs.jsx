import React, { useState } from 'react'
import regionCodes from '../../resources/regions.txt?raw'

const names = new Intl.DisplayNames(['zh-CN'], {type:'region'})
const regions = regionCodes.trim().split(/\s+/).map(code=>({ code, name:names.of(code) }))
const time = seconds => seconds ? new Date(seconds*1000).toLocaleString() : '尚未更新'

export default function CacheJobs({ state, isAdmin, busy, save, refresh, run }) {
  const [changes,setChanges] = useState({})
  const [token,setToken] = useState('')
  const [clear,setClear] = useState(false)
  const [search,setSearch] = useState('')
  const draft = {...state.settings,...changes}
  const edit = patch => setChanges(old=>({...old,...patch}))
  const query = search.trim().toLowerCase()
  const dirty = Object.keys(changes).length > 0 || clear || token !== ''
  const apply = () => run(async ()=>{
    await save({...draft,...(clear || token ? {token:clear ? '' : token} : {})})
    setChanges({}); setToken(''); setClear(false)
  })
  return <section className="panel"><div className="panel-head"><h2>缓存预加载</h2></div><div className="policy-body">
    <label className="policy-check"><input type="checkbox" checked={draft.ns} disabled={busy || !isAdmin || state.custom_roots} onChange={e=>edit({ns:e.target.checked})}/>顶级域名 NS 缓存</label>
    {state.custom_roots ? <p>当前使用自定义根服务器，公共根区快照不可用。</p> : <p>{state.root ? `版本 ${state.root.serial} · ${state.root.count} 个顶级域名 · ${time(state.root.checked_at)}` : '启用后按根区 SOA 周期更新 SQLite 快照。'}</p>}
    {state.settings.ns && state.root_error && <p className="notice error">{state.root_error}</p>}
    {isAdmin && <button className="btn tertiary" disabled={busy || dirty || !state.settings.ns} onClick={()=>run(()=>refresh('ns'))}>立即刷新 NS 快照</button>}
    <label className="policy-check"><input type="checkbox" checked={draft.radar} disabled={!isAdmin || busy} onChange={e=>edit({radar:e.target.checked})}/>地区热点域名预热</label>
    <p>每日获取地区 Top 100，并从 Cisco Umbrella 补充匹配子域名。公开榜单用于填补本地热点未占满的预热名额。</p>
    {isAdmin && <><label>Cloudflare API Token<input type="password" autoComplete="new-password" disabled={clear || busy} value={token} placeholder={state.token_configured ? '已配置，留空保留' : '输入 API Token'} onChange={e=>setToken(e.target.value)}/></label>
      {state.token_configured && <label className="policy-check"><input type="checkbox" disabled={busy} checked={clear} onChange={e=>setClear(e.target.checked)}/>清除已保存的 Token</label>}
      <label className="policy-check"><input type="checkbox" disabled={busy} checked={draft.global_top_1000} onChange={e=>edit({global_top_1000:e.target.checked})}/>补充 Cloudflare 全球 Top 1,000（每周更新）</label>
      <label>搜索国家或地区<input value={search} onChange={e=>setSearch(e.target.value)} placeholder="名称或两位地区代码"/></label>
      <fieldset className="radar-regions" disabled={busy}><legend>国家或地区（已选 {draft.regions.length}）</legend>{regions.filter(({code,name})=>name.includes(query)||code.toLowerCase().includes(query)).map(({code,name})=><label className="policy-check" key={code}><input type="checkbox" checked={draft.regions.includes(code)} onChange={e=>edit({regions:e.target.checked ? [...draft.regions,code] : draft.regions.filter(c=>c!==code)})}/>{name} · {code}</label>)}</fieldset>
    </>}
    <fieldset className="policy-grid" disabled={!isAdmin || busy}>
      <legend>预热名单</legend>
      <label>预热域名总数上限<input type="number" min="1" max="100000" value={draft.warm_domain_limit} onChange={e=>edit({warm_domain_limit:Number(e.target.value)})}/></label>
      <label className="policy-check"><input type="checkbox" checked={draft.local_hot_enabled} onChange={e=>edit({local_hot_enabled:e.target.checked})}/>优先预热本机高频域名</label>
      {draft.local_hot_enabled && <>
        <label>本地统计窗口（小时）<input type="number" min="1" max="168" value={draft.local_window_hours} onChange={e=>edit({local_window_hours:Number(e.target.value)})}/></label>
        <label>高频门槛（查询次数）<input type="number" min="1" max="50000" value={draft.local_min_queries} onChange={e=>edit({local_min_queries:Number(e.target.value)})}/></label>
        <p className="full-width policy-help">每分钟从最近最多 50,000 条客户端请求中统计，优先预热实际查询的记录类型。</p>
      </>}
    </fieldset>
    {state.warm_candidates && <details>
      <summary>当前名单：本机 {state.warm_candidates.local_domains} 个 · 公开榜单 {state.warm_candidates.public_domains} 个</summary>
      {state.warm_candidates.local_preview.length ? <div className="table-wrap"><table><thead><tr><th>本机域名（前 20）</th><th>查询次数</th><th>记录类型</th></tr></thead><tbody>
        {state.warm_candidates.local_preview.map(item=><tr key={item.domain}><td>{item.domain}</td><td>{item.count}</td><td>{item.kinds.join('、')}</td></tr>)}
      </tbody></table></div> : <p>暂无达到当前高频门槛的域名。</p>}
    </details>}
    {draft.regions.length>0 && <p>{draft.regions.map(code=>names.of(code)).join('、')}</p>}
    {state.umbrella && <p>Umbrella 子域名 {state.umbrella.count} 个 · {time(state.umbrella.updated_at)} {state.umbrella.error}</p>}
    {state.rankings.length>0 && <div className="table-wrap"><table><thead><tr><th>地区</th><th>榜单日期</th><th>域名数</th><th>最近成功</th><th>错误</th></tr></thead><tbody>{state.rankings.map(row=><tr key={row.region}><td>{row.region==='GLOBAL'?'全球 Top 1,000':names.of(row.region)}</td><td>{row.date || '—'}</td><td>{row.count}</td><td>{time(row.updated_at)}</td><td>{row.error || '—'}</td></tr>)}</tbody></table></div>}
    {isAdmin && <div className="policy-actions"><button className="btn tertiary" disabled={busy || dirty || !(state.settings.radar || state.settings.local_hot_enabled)} onClick={()=>run(()=>refresh('radar'))}>立即刷新预热名单</button><button className="btn primary" disabled={busy || !dirty} onClick={apply}>保存缓存预加载配置</button></div>}
  </div></section>
}
