import { useRef, useEffect, useState } from 'react'

const CONFIG = {
  SAFE: { color: 'var(--neon)', glow: 'var(--neon-glow)', icon: '🛡️', label: 'SYSTEM SECURE', desc: 'All monitored sessions within normal behavioral range.' },
  SUSPICIOUS: { color: 'var(--amber)', glow: 'var(--amber-glow)', icon: '⚠️', label: 'ELEVATED WATCH', desc: 'Anomalous signals detected — sessions under closer monitoring.' },
  LOCKDOWN: { color: 'var(--red)', glow: 'var(--red-glow)', icon: '🔒', label: 'LOCKDOWN ACTIVE', desc: 'One or more sessions frozen pending admin authentication.' },
}

export default function StatusIndicator({ overallStatus }) {
  const cfg = CONFIG[overallStatus] || CONFIG.SAFE
  const prevRef = useRef(overallStatus)
  const [transitioning, setTransitioning] = useState(false)

  // Flash transition effect when status changes
  useEffect(() => {
    if (prevRef.current !== overallStatus) {
      prevRef.current = overallStatus
      setTransitioning(true)
      const t = setTimeout(() => setTransitioning(false), 600)
      return () => clearTimeout(t)
    }
  }, [overallStatus])

  return (
    <div
      className={`glass status-hero glowing-border${transitioning ? ' status-transitioning' : ''}`}
      data-status={overallStatus}
    >
      {/* Ambient status glow overlay */}
      <div
        className="status-hero-glow"
        style={{ background: `radial-gradient(circle at 20% 50%, ${cfg.glow.replace(')', ', 0.12)').replace('rgba', 'rgba')}, transparent 65%)` }}
      />

      <div
        className={`status-ring status-ring-${(overallStatus || 'SAFE').toLowerCase()}`}
        style={{ '--ring-color': cfg.color, '--ring-glow': cfg.glow }}
      >
        {/* Outer scanning arc */}
        <div className="status-ring-sweep" />
        <span className="status-icon">{cfg.icon}</span>
      </div>

      <div className="status-text">
        <h2 style={{ color: cfg.color, textShadow: `0 0 14px ${cfg.glow}` }}>
          {cfg.label}
        </h2>
        <p>{cfg.desc}</p>

        {/* Live telemetry indicators */}
        <div className="status-telemetry">
          <span className="status-dot" style={{ background: cfg.color, boxShadow: `0 0 6px ${cfg.glow}` }} />
          <span style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.12em' }}>
            REAL-TIME // CYBERMIND AI ENGINE ACTIVE
          </span>
        </div>
      </div>
    </div>
  )
}
