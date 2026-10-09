import { useEffect, useMemo, useRef, useState } from 'react'

/** Ctrl/Cmd+K palette. items: [{ id, label, hint, run }] */
export default function CommandPalette({ open, onClose, items }) {
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const inputRef = useRef(null)

  const results = useMemo(() => {
    const s = q.trim().toLowerCase()
    return s ? items.filter((i) => (i.label + ' ' + (i.hint || '')).toLowerCase().includes(s)) : items
  }, [q, items])

  useEffect(() => { if (open) { setQ(''); setIdx(0); setTimeout(() => inputRef.current?.focus(), 30) } }, [open])
  useEffect(() => { setIdx(0) }, [q])

  if (!open) return null

  const run = (item) => { if (!item) return; onClose(); item.run() }
  const onKey = (e) => {
    if (e.key === 'Escape') onClose()
    else if (e.key === 'ArrowDown') { e.preventDefault(); setIdx((i) => Math.min(i + 1, results.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx((i) => Math.max(i - 1, 0)) }
    else if (e.key === 'Enter') run(results[idx])
  }

  return (
    <div className="cm-palette-wrap" onMouseDown={onClose}>
      <div className="cm-palette" onMouseDown={(e) => e.stopPropagation()} role="dialog" aria-label="Quick actions">
        <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} placeholder="Jump to a view or run an action…" />
        <div className="cm-palette-list">
          {results.length === 0 && <div className="cm-palette-empty mono">No matches</div>}
          {results.map((r, i) => (
            <button key={r.id} className={i === idx ? 'on' : ''} onMouseEnter={() => setIdx(i)} onClick={() => run(r)}>
              <span>{r.label}</span>
              {r.hint && <em className="mono">{r.hint}</em>}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
