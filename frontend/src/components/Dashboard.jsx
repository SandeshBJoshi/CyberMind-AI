import { useEffect, useMemo, useRef, useState } from 'react'
import MetricCard from './MetricCard'
import ActivityFeed from './ActivityFeed'
import ThreatGauge from './ThreatGauge'
import SessionOrbit from './SessionOrbit'
import PulseChart, { bucketize } from './PulseChart'
import { getEmailStats, startSession, startNormalTraffic, stopNormalTraffic, getSessions, getSecurityStatus, getMlStatus, retrainModel } from '../api'

const COPY = {
  SAFE: { title: 'SYSTEM SECURE', desc: 'All monitored sessions within normal behavioral range.' },
  SUSPICIOUS: { title: 'ELEVATED WATCH', desc: 'Anomalous signals detected — sessions under closer monitoring.' },
  LOCKDOWN: { title: 'LOCKDOWN ACTIVE', desc: 'One or more sessions frozen pending admin authentication.' },
}

// Threat index: recent events weighted by severity and decayed over time.
function threatScore(events, now, locked) {
  let s = locked > 0 ? 38 : 0
  for (const e of events) {
    if (!e._t) continue
    const age = (now - e._t) / 1000
    if (age > 180) continue
    const w = e.status === 'LOCKDOWN' ? 26 : e.status === 'SUSPICIOUS' ? 7 : 0.35
    s += w * Math.exp(-age / 55)
  }
  return Math.min(100, s)
}

export default function Dashboard({ events, lockedSessionIds, setView, pulse = 0 }) {
  const [simSessionId, setSimSessionId] = useState(null)
  const [normalRunning, setNormalRunning] = useState(false)
  const [sessionCount, setSessionCount] = useState(0)
  const [sessionHistory, setSessionHistory] = useState([])
  const [now, setNow] = useState(Date.now())
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [posture, setPosture] = useState(null)
  const [ml, setMl] = useState(null)
  const [mlMsg, setMlMsg] = useState('')
  const alive = useRef(true)
  const [emailStats, setEmailStats] = useState(null)
  useEffect(() => { getEmailStats().then(setEmailStats).catch(() => {}) }, [pulse])

  useEffect(() => {
    alive.current = true
    const tick = setInterval(() => setNow(Date.now()), 1000)
    const poll = async () => {
      try {
        const sessions = await getSessions().catch(() => [])
        if (!alive.current) return
        setSessionCount(sessions.length || 0)
        setSessionHistory((h) => [...h, sessions.length || 0].slice(-24))
      } catch { /* not logged in yet */ }
    }
    poll()
    getSecurityStatus().then(setPosture).catch(() => {})
    getMlStatus().then(setMl).catch(() => {})
    const interval = setInterval(poll, 4000)
    return () => { alive.current = false; clearInterval(tick); clearInterval(interval) }
  }, [])

  const overallStatus = lockedSessionIds.size > 0
    ? 'LOCKDOWN'
    : (events.some((e) => e.status === 'SUSPICIOUS') ? 'SUSPICIOUS' : 'SAFE')
  const copy = COPY[overallStatus]

  const lockdownCount = events.filter((e) => e.status === 'LOCKDOWN').length
  const suspiciousCount = events.filter((e) => e.status === 'SUSPICIOUS').length
  const score = useMemo(() => threatScore(events, now, lockedSessionIds.size), [events, now, lockedSessionIds])

  const perMinute = events.filter((e) => e._t && now - e._t < 60000).length
  const sparkAll = bucketize(events, now).slice(-14)
  const sparkSus = bucketize(events, now, 'SUSPICIOUS').slice(-14)
  const sparkLock = bucketize(events, now, 'LOCKDOWN').slice(-14)

  async function guard(fn) {
    setBusy(true); setError('')
    try { await fn() } catch (e) { setError(e.message || 'Request failed') } finally { setBusy(false) }
  }
  const handleCreateSession = () => guard(async () => { const res = await startSession('demo_user'); setSimSessionId(res.session_id) })
  const handleToggleNormal = () => guard(async () => {
    if (normalRunning) { await stopNormalTraffic(); setNormalRunning(false) }
    else { await startNormalTraffic(); setNormalRunning(true) }
  })

  return (
    <div className="cm-dash">
      <section className="cm-hero">
        <div className="cm-hero-copy">
          <div className="cm-eyebrow mono"><span className="cm-dot" /> CYBERMIND AI · REAL-TIME ENGINE ACTIVE</div>
          <h1>{copy.title}</h1>
          <p>{copy.desc}</p>
          <div className="cm-chips mono">
            <span>ENGINE · Isolation Forest + 6 rules</span>
            <span>FEED · WebSocket</span>
            <span>RESPONSE · Auto-lockdown</span>
          </div>
        </div>
        <div className="cm-hero-3d">
          <SessionOrbit sessions={sessionCount} locked={lockedSessionIds.size} threat={overallStatus} pulse={pulse} />
          <div className="cm-hero-gauge"><ThreatGauge score={score} /></div>
        </div>
      </section>

      <div className="cm-metrics">
        <MetricCard label="ACTIVE SESSIONS" value={sessionCount} accent="neon" hint="monitored now" spark={sessionHistory} />
        <MetricCard label="EVENTS / MIN" value={perMinute} accent="safe" hint="live telemetry" spark={sparkAll} />
        <MetricCard label="SUSPICIOUS EVENTS" value={suspiciousCount} accent="amber" hint="flagged by engine" spark={sparkSus} />
        <MetricCard label="PHISHING EMAILS" value={emailStats ? emailStats.phishing : 0} accent="red" hint={emailStats ? `${emailStats.total} analysed` : 'email analysis'} />
        <MetricCard label="LOCKDOWNS TRIGGERED" value={lockdownCount} accent="red" hint="auto-triggered" spark={sparkLock} />
      </div>

      <div className="cm-split">
        <div className="cm-col">
          <PulseChart events={events} now={now} />
          <ActivityFeed events={events} now={now} />
        </div>

        <div className="cm-col">
          <div className="cm-card">
            <div className="cm-card-head"><div className="cm-card-title"><i />Demo / Red Team Controls</div></div>
            <p className="cm-muted">
              Generate synthetic baseline traffic or launch manual red team technique vectors via the Attack Simulator.
            </p>
            <div className="cm-actions">
              <button className="cm-btn warn" onClick={() => setView && setView('attacker')}>
                <span>⚡</span> OPEN ATTACK SIMULATOR
              </button>
              <button className="cm-btn" onClick={handleToggleNormal} disabled={busy}>
                <span>{normalRunning ? '■' : '▶'}</span> {normalRunning ? 'STOP NORMAL TRAFFIC SIMULATION' : 'START NORMAL TRAFFIC SIMULATION'}
              </button>
              <button className="cm-btn" onClick={handleCreateSession} disabled={busy}>
                <span>＋</span> CREATE DEMO SESSION {simSessionId ? <em className="mono">{simSessionId.slice(0, 8)}</em> : null}
              </button>
            </div>
            {error && <div className="cm-error">⚠ {error}</div>}
            <div className="cm-note">
              The attack simulation fires bot-like keystroke rhythm, IP/device churn, repeated failed logins, and an API
              request burst — designed to trip both the rule engine and the ML anomaly detector so you can watch
              lockdown trigger automatically.
            </div>
          </div>

          <div className="cm-card">
            <div className="cm-card-head">
              <div className="cm-card-title"><i />Hardening status</div>
              {posture && <span className={`cm-count mono${posture.mode === 'production' ? '' : ' warnpill'}`}>{posture.mode.toUpperCase()}</span>}
            </div>
            {!posture ? <div className="cm-empty small">Loading…</div> : (
              <ul className="posture">
                {posture.checks.map((c) => <li key={c.id} className={c.ok ? 'ok' : 'bad'}><span>{c.ok ? '✓' : '⚠'}</span>{c.label}</li>)}
              </ul>
            )}
            {ml && (
              <div className="cm-note" style={{ marginTop: 12 }}>
                Detection model trained on <b>{ml.source.replace('-', ' ')}</b> data. {ml.real_safe_events} real safe events recorded (need {ml.needed_to_retrain}).
                <button className="pro-btn sm" style={{ marginTop: 8 }} disabled={ml.real_safe_events < ml.needed_to_retrain}
                  onClick={() => retrainModel().then((r) => { setMlMsg(r.retrained ? `Retrained on ${r.rows} real events.` : r.reason); getMlStatus().then(setMl) }).catch((e) => setMlMsg(e.message))}>
                  Learn from real traffic
                </button>
                {mlMsg && <div style={{ marginTop: 6 }}>{mlMsg}</div>}
              </div>
            )}
          </div>

          <div className="cm-card">
            <div className="cm-card-head"><div className="cm-card-title"><i />Lockdown containment</div></div>
            {lockedSessionIds.size === 0 ? (
              <div className="cm-empty small"><span>✓</span>No sessions are frozen.</div>
            ) : (
              <div className="cm-locked-list">
                {[...lockedSessionIds].map((id) => (
                  <button key={id} className="cm-locked" onClick={() => setView && setView('sessions')}>
                    <span className="cm-lock-ico">🔒</span>
                    <span className="mono">{id.slice(0, 8)}</span>
                    <em>Review &amp; unlock →</em>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
