/** Radial threat index (0–100). Colour comes from --threat on the nearest .cm-app. */
export default function ThreatGauge({ score = 0, label = 'THREAT INDEX' }) {
  const R = 58, C = 2 * Math.PI * R, arc = 0.75 // 270° gauge
  const filled = (Math.max(0, Math.min(100, score)) / 100) * C * arc
  const ticks = Array.from({ length: 28 }, (_, i) => {
    const a = (-225 + (i / 27) * 270) * (Math.PI / 180)
    const on = i / 27 <= score / 100
    return <line key={i} x1={80 + Math.cos(a) * 68} y1={80 + Math.sin(a) * 68} x2={80 + Math.cos(a) * (on ? 75 : 72)} y2={80 + Math.sin(a) * (on ? 75 : 72)} className={on ? 'on' : ''} />
  })
  return (
    <div className="cm-gauge" role="img" aria-label={`${label} ${Math.round(score)} out of 100`}>
      <svg viewBox="0 0 160 160">
        <circle cx="80" cy="80" r={R} className="track" strokeDasharray={`${C * arc} ${C}`} transform="rotate(135 80 80)" />
        <circle cx="80" cy="80" r={R} className="fill" strokeDasharray={`${filled} ${C}`} transform="rotate(135 80 80)" />
        <g className="ticks">{ticks}</g>
      </svg>
      <div className="cm-gauge-num"><b>{Math.round(score)}</b><span className="mono">{label}</span></div>
    </div>
  )
}
