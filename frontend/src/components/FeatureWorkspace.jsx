import { useEffect, useRef } from 'react'

/**
 * FeatureWorkspace — the "tab" that opens when you click a station in the neuron.
 * The feature is built from separate pieces (its cards, columns and panels). On open they ASSEMBLE out of
 * 3D space one by one; on close they DISMANTLE and scatter back into the network.
 */
const SEL = [
  '.cm-ws-bar', '.cm-card', '.cm-metric', '.cm-hero-copy', '.cm-hero-3d', '.cm-page-head', '.cm-session',
  '.cm-portal-frame', '.glass', '.panel', '.cybermind-hero', '.attacker-header',
].join(',')

// outermost pieces only (a card inside a card moves with its parent)
function pieces(root) {
  if (!root) return []
  const all = [...root.querySelectorAll(SEL)]
  return all.filter((el) => !all.some((o) => o !== el && o.contains(el)))
}

// deterministic pseudo-random scatter so each piece flies from / to its own place
const rnd = (i, m) => { const x = Math.sin(i * 12.9898 + m * 78.233) * 43758.5453; return x - Math.floor(x) }
function scatter(i, k = 1) {
  return { x: (rnd(i, 1) - 0.5) * 1000 * k, y: (rnd(i, 2) - 0.5) * 620 * k, z: -(480 + rnd(i, 3) * 760) * k, rx: (rnd(i, 4) - 0.5) * 80, ry: (rnd(i, 5) - 0.5) * 100, rz: (rnd(i, 6) - 0.5) * 34 }
}
const tf = (a) => `translate3d(${a.x}px, ${a.y}px, ${a.z}px) rotateX(${a.rx}deg) rotateY(${a.ry}deg) rotateZ(${a.rz}deg) scale(0.7)`
const reduced = () => typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

export default function FeatureWorkspace({ station, index, total, closing, onClosed, onClose, onPrev, onNext, children }) {
  const root = useRef(null)
  const seen = useRef(new WeakSet())

  // ASSEMBLE — also sweeps again shortly after, to catch pieces that render once data arrives
  useEffect(() => {
    const run = () => {
      const els = pieces(root.current).filter((e) => !seen.current.has(e))
      els.forEach((el, i) => {
        seen.current.add(el)
        if (reduced()) return
        el.animate(
          [{ opacity: 0, transform: tf(scatter(i)), filter: 'blur(14px)' }, { opacity: 1, transform: 'none', filter: 'blur(0px)' }],
          { duration: 1050, delay: 120 + i * 85, easing: 'cubic-bezier(0.16, 1, 0.3, 1)', fill: 'backwards' },
        )
      })
    }
    run()
    const t1 = setTimeout(run, 650), t2 = setTimeout(run, 1600)
    return () => { clearTimeout(t1); clearTimeout(t2) }
  }, [station.id])

  // DISMANTLE
  useEffect(() => {
    if (!closing) return
    const els = pieces(root.current)
    let end = 0
    if (!reduced()) {
      els.forEach((el, i) => {
        const delay = i * 50
        end = Math.max(end, delay + 680)
        el.animate(
          [{ opacity: 1, transform: 'none', filter: 'blur(0px)' }, { opacity: 0, transform: tf(scatter(i + 11, 1.35)), filter: 'blur(12px)' }],
          { duration: 680, delay, easing: 'cubic-bezier(0.55, 0, 0.9, 0.4)', fill: 'forwards' },
        )
      })
    }
    const t = setTimeout(onClosed, end + 60)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [closing])

  return (
    <div className={`cm-ws${closing ? ' closing' : ''}`} ref={root} role="dialog" aria-label={station.name}>
      <div className="cm-ws-bar">
        <button className="cm-ws-back" onClick={onClose}>← Back to network</button>
        <div className="cm-ws-title">
          <b className="mono">{String(index + 1).padStart(2, '0')} / {String(total).padStart(2, '0')} · {station.depth}</b>
          <h2>{station.name}</h2>
          <span>{station.line}</span>
        </div>
        <div className="cm-ws-nav">
          <button onClick={onPrev} disabled={index === 0} aria-label="Previous feature">‹</button>
          <button onClick={onNext} disabled={index === total - 1} aria-label="Next feature">›</button>
          <kbd className="mono">Esc</kbd>
        </div>
      </div>
      <div className="cm-ws-body">{children}</div>
    </div>
  )
}
