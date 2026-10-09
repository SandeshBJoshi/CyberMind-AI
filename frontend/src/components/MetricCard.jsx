import { useEffect, useRef, useState } from 'react'

function Spark({ data }) {
  if (!data || data.length < 2) return <div className="cm-spark empty" />
  const W = 120, H = 34, max = Math.max(...data), min = Math.min(...data)
  const span = max - min
  const pts = data.map((v, i) => [(i / (data.length - 1)) * W, span === 0 ? H * 0.6 : H - 4 - ((v - min) / span) * (H - 10)])
  const line = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ')
  return (
    <svg className="cm-spark" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true">
      <path d={`${line} L${W} ${H} L0 ${H} Z`} className="area" />
      <path d={line} className="line" />
    </svg>
  )
}

/**
 * MetricCard — animated counter, sparkline and spotlight hover.
 * Props: label, value (number), accent ('neon'|'amber'|'red'|'safe'), hint, spark (number[]), suffix
 */
export default function MetricCard({ label, value, accent = 'neon', hint, spark, suffix = '' }) {
  const [shown, setShown] = useState(value)
  const prev = useRef(value)
  const raf = useRef(0)
  const ref = useRef(null)

  useEffect(() => {
    const from = prev.current, to = value
    prev.current = to
    if (from === to) return
    const t0 = performance.now()
    const step = (now) => {
      const k = Math.min((now - t0) / 650, 1)
      setShown(Math.round(from + (to - from) * (1 - Math.pow(1 - k, 3))))
      if (k < 1) raf.current = requestAnimationFrame(step)
    }
    cancelAnimationFrame(raf.current)
    raf.current = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf.current)
  }, [value])

  const onMove = (e) => {
    const r = ref.current.getBoundingClientRect()
    ref.current.style.setProperty('--mx', `${e.clientX - r.left}px`)
    ref.current.style.setProperty('--my', `${e.clientY - r.top}px`)
  }

  return (
    <div ref={ref} className={`cm-card cm-metric acc-${accent}`} onMouseMove={onMove}>
      <div className="cm-metric-top">
        <span className="cm-metric-label mono">{label}</span>
        <span className="cm-metric-dot" />
      </div>
      <div className="cm-metric-value">{shown}<small>{suffix}</small></div>
      <div className="cm-metric-bottom">
        <span className="cm-metric-hint">{hint}</span>
        <Spark data={spark} />
      </div>
    </div>
  )
}
