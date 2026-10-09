function ago(t, now) {
  if (!t) return ''
  const s = Math.max(0, Math.round((now - t) / 1000))
  return s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ago`
}

function FeedItem({ event: e, now }) {
  const cls = e.status === 'LOCKDOWN' ? 'lock' : e.status === 'SUSPICIOUS' ? 'sus' : 'safe'
  return (
    <div className={`cm-feed-item ${cls}`}>
      <span className="cm-feed-rail" />
      <div className="cm-feed-main">
        <div className="cm-feed-line">
          <strong>{e.event_type}</strong>
          <span className="mono-id">{e.session_id?.slice(0, 8)}</span>
          <span className="cm-feed-time mono">{ago(e._t, now)}</span>
        </div>
        {((e.rule_flags && e.rule_flags.length > 0) || e.ml_anomaly) && (
          <div className="cm-feed-tags">
            {(e.rule_flags || []).map((f, i) => <span className="tag" key={i}>{f}</span>)}
            {e.ml_anomaly && <span className="tag tag-ml">ml_anomaly</span>}
          </div>
        )}
      </div>
      <span className={`cm-badge ${cls}`}>{e.status}</span>
    </div>
  )
}

export default function ActivityFeed({ events, now = Date.now() }) {
  return (
    <div className="cm-card cm-feed-card">
      <div className="cm-card-head">
        <div className="cm-card-title"><i />Live Activity Feed{events.length > 0 && <span className="cm-live mono">LIVE</span>}</div>
        <span className="mono cm-count">{events.length}</span>
      </div>
      <div className="cm-feed">
        {events.length === 0 && (
          <div className="cm-empty"><span>◈</span>Waiting for behavioral telemetry…</div>
        )}
        {events.slice(0, 40).map((e, i) => <FeedItem key={`${e.session_id}-${e._t || i}-${i}`} event={e} now={now} />)}
      </div>
    </div>
  )
}
