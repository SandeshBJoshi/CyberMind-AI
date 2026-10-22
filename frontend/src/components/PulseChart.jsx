/**
 * PulseChart — stacked bar timeline of live events (last 2 minutes, 5 s buckets).
 * Events need an arrival timestamp `_t` (stamped in App when the WebSocket delivers them).
 */
export const BUCKET_MS = 5000
export const BUCKETS = 24

export function bucketize(events, now, status) {
  const out = new Array(BUCKETS).fill(0)
  for (const e of events) {
    if (!e._t || (status && e.status !== status)) continue
    const age = now - e._t
    if (age < 0 || age >= BUCKET_MS * BUCKETS) continue
    out[BUCKETS - 1 - Math.floor(age / BUCKET_MS)]++
  }
  return out
}

export default function PulseChart({ events, now }) {
  const safe = bucketize(events, now, 'SAFE')
  const sus = bucketize(events, now, 'SUSPICIOUS')
  const lock = bucketize(events, now, 'LOCKDOWN')
  const totals = safe.map((v, i) => v + sus[i] + lock[i])
  const max = Math.max(4, ...totals)
  const W = 720, H = 190, pad = 8, bw = (W - pad * 2) / BUCKETS
  const total = totals.reduce((a, b) => a + b, 0)

  return (
    <div className="cm-card cm-chart">
      <div className="cm-card-head">
        <div className="cm-card-title"><i />Event pulse</div>
        <div className="cm-legend mono"><span className="s">SAFE</span><span className="a">SUSPICIOUS</span><span className="r">LOCKDOWN</span></div>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="cm-chart-svg" role="img" aria-label="Events over the last two minutes">
        {[0.25, 0.5, 0.75].map((g) => <line key={g} x1="0" x2={W} y1={H - 20 - (H - 40) * g} y2={H - 20 - (H - 40) * g} className="grid" />)}
        {totals.map((t, i) => {
          const x = pad + i * bw + 2, w = bw - 4, h = (H - 40) / max
          const hs = safe[i] * h, ha = sus[i] * h, hl = lock[i] * h
          const base = H - 20
          return (
            <g key={i} className={i === BUCKETS - 1 ? 'live' : ''}>
              <rect x={x} y={base - hs} width={w} height={hs} rx="2" className="bs" />
              <rect x={x} y={base - hs - ha} width={w} height={ha} rx="2" className="ba" />
              <rect x={x} y={base - hs - ha - hl} width={w} height={hl} rx="2" className="br" />
              {t === 0 && <rect x={x} y={base - 2} width={w} height="2" rx="1" className="bz" />}
            </g>
          )
        })}
      </svg>
      <div className="cm-chart-foot mono"><span>−2 min</span><span>{total} events in window</span><span>now</span></div>
    </div>
  )
}
