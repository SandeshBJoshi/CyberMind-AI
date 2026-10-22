import { useState, useEffect, useRef } from 'react'
import {
  getSessions,
  startSession,
  protectedAction,
  unlockSession,
  sendApiRequest,
  execIdentityChurn,
} from '../api'
import { shortDevice } from '../lib/ua'
import AttackLab from './AttackLab'

const LEVEL_ICON = { sys: '·', info: '＋', cmd: '❯', success: '✓', warn: '▲', error: '✕' }
const LEVEL_FILTERS = [['all', 'ALL'], ['info', 'INFO'], ['warn', 'WARN'], ['error', 'ERROR']]
const matchLevel = (type, f) => f === 'all' || (f === 'info' ? ['sys', 'info', 'cmd', 'success'].includes(type) : type === f)

// Estimated-risk gauge (semicircle) with the lockdown threshold marked
function RiskGauge({ score, max }) {
  const pct = Math.min(score / max, 1)
  const L = Math.PI * 80
  const tone = pct >= 1 ? 'lock' : pct >= 0.5 ? 'sus' : 'safe'
  return (
    <div className={`atk-gauge ${tone}`}>
      <svg viewBox="0 0 200 118" role="img" aria-label={`Estimated risk ${score.toFixed(1)} of ${max}`}>
        <path d="M20 100 A80 80 0 0 1 180 100" className="track" />
        <path d="M20 100 A80 80 0 0 1 180 100" className="fill" strokeDasharray={`${pct * L} ${L}`} />
        <line x1="180" y1="100" x2="196" y2="100" className="thr" />
        <text x="100" y="86" textAnchor="middle" className="num">{score.toFixed(1)}</text>
        <text x="100" y="106" textAnchor="middle" className="den">of {max} lockdown threshold</text>
      </svg>
      <div className="atk-gauge-state mono">{pct >= 1 ? 'LOCKDOWN THRESHOLD REACHED' : pct >= 0.5 ? 'SUSPICIOUS ZONE' : 'SAFE'}</div>
    </div>
  )
}

export default function AttackerConsole() {
  const [sessions, setSessions] = useState([])
  const [targetSessionId, setTargetSessionId] = useState('')
  const [targetStatus, setTargetStatus] = useState('UNKNOWN')
  const [activeTab, setActiveTab] = useState('t1090')
  const [terminalLogs, setTerminalLogs] = useState([
    {
      id: 1,
      time: new Date().toLocaleTimeString(),
      type: 'sys',
      text: 'CYBERMIND AI Red Team Console initialized. Select target session & attack technique to begin.'
    }
  ])
  const [executing, setExecuting] = useState(false)
  const [unlocking, setUnlocking] = useState(false)
  const [protectedTestResult, setProtectedTestResult] = useState(null)
  const [levelFilter, setLevelFilter] = useState('all')
  const [mode, setMode] = useState('manual') // manual | lab
  const [chain, setChain] = useState({ evade: false, flood: false }) // kill-chain progress for the current target

  // Risk meter state (event-fired approximation of risk score)
  const [riskScore, setRiskScore] = useState(0)
  const LOCKDOWN_THRESHOLD = 6.0  // matches backend default lockdown_threshold in config.py

  // Terminal scroll ref
  const terminalBodyRef = useRef(null)

  // Technique 1: IP Change (T1090 Identity Churn)
  const [churnIp, setChurnIp] = useState('185.220.101.5')
  const [churnDevice, setChurnDevice] = useState('Tor-Exit-Node/7.0')

  // Technique 2: API Request Attack (T1499)
  const [burstCount, setBurstCount] = useState(75)
  const [burstEndpoint, setBurstEndpoint] = useState('/api/v1/user/export')
  const [burstIp, setBurstIp] = useState('45.134.26.7')
  const [burstDevice, setBurstDevice] = useState('python-requests/2.31.0')
  const [burstProgress, setBurstProgress] = useState({ sent: 0, completed: 0, rate: 0 })

  // Auto-scroll the terminal (not the whole page) whenever logs change
  useEffect(() => {
    const el = terminalBodyRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [terminalLogs, levelFilter])

  useEffect(() => {
    loadSessions()
    const interval = setInterval(loadSessions, 3000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    if (sessions.length > 0 && !targetSessionId) {
      setTargetSessionId(sessions[0].session_id)
      setTargetStatus(sessions[0].status)
    } else if (targetSessionId) {
      const match = sessions.find(s => s.session_id === targetSessionId)
      if (match) setTargetStatus(match.status)
    }
  }, [sessions, targetSessionId])

  // Reset risk meter + kill chain when target session changes
  useEffect(() => {
    setRiskScore(0)
    setChain({ evade: false, flood: false })
  }, [targetSessionId])

  async function loadSessions() {
    try {
      const list = await getSessions()
      setSessions(list || [])
    } catch { /* ignore if unauthed */ }
  }

  async function handleSpawnSandbox() {
    try {
      const res = await startSession(`attacker_target_${Math.floor(Math.random() * 1000)}`)
      logTerminal('info', `[+] Created new target sandbox session: ${res.session_id}`)
      await loadSessions()
      setTargetSessionId(res.session_id)
      setTargetStatus(res.status || 'SAFE')
      setRiskScore(0)
    } catch (err) {
      logTerminal('error', `[-] Failed to spawn sandbox: ${err.message}`)
    }
  }

  async function handleUnlockTarget() {
    if (!targetSessionId) return
    setUnlocking(true)
    logTerminal('cmd', `[>] Sending admin unlock command for session ${targetSessionId.slice(0, 8)}...`)
    try {
      await unlockSession(targetSessionId)
      logTerminal('success', `[✓] Session ${targetSessionId.slice(0, 8)} has been unlocked. Target is ACTIVE again.`)
      setRiskScore(0)
      setChain({ evade: false, flood: false })
      await loadSessions()
    } catch (err) {
      logTerminal('error', `[-] Unlock failed: ${err.message}`)
    } finally {
      setUnlocking(false)
    }
  }

  function logTerminal(level, text, data = null) {
    const entry = {
      id: Date.now() + Math.random(),
      time: new Date().toLocaleTimeString(),
      type: level,
      text,
      data
    }
    setTerminalLogs(prev => [...prev.slice(-200), entry])
  }

  function bumpRiskScore(res) {
    const status = res.status || res.final_status || 'SAFE'
    setRiskScore(prev => {
      if (status === 'LOCKDOWN') return LOCKDOWN_THRESHOLD
      if (status === 'SUSPICIOUS' || status === 'SHADOW') return Math.min(prev + 2.5, LOCKDOWN_THRESHOLD - 0.1)
      return Math.min(prev + 0.5, LOCKDOWN_THRESHOLD)
    })
  }

  async function handleTestProtectedAction() {
    if (!targetSessionId) return
    logTerminal('cmd', `[>] Testing protected action '/api/protected-action' on session ${targetSessionId.slice(0, 8)}...`)
    const res = await protectedAction(targetSessionId, 'transfer_funds')
    setProtectedTestResult(res)
    if (res.ok && targetStatus === 'SHADOW') {
      logTerminal('warn', `[◐] Looks allowed to the attacker (200 OK), but this session is in SHADOW MODE: the attempt is recorded and nothing real executes.`, res.data)
    } else if (res.ok) {
      logTerminal('success', `[✓] Action Allowed (200 OK): Protected action executed successfully on active session.`, res.data)
    } else {
      logTerminal('error', `[🛑] ACTION BLOCKED (${res.status}): ${res.data.detail || 'Session is locked!'}`, res.data)
    }
  }

  // API Request Attack — fires real authenticated POST /user/behavior requests
  async function handleApiRequestBurst() {
    if (!targetSessionId) {
      logTerminal('error', '[-] Error: Select or create a target session before launching attack!')
      return
    }

    const count = Math.max(1, Math.floor(Number(burstCount) || 1))
    const startedAt = performance.now()
    setExecuting(true)
    setBurstProgress({ sent: count, completed: 0, rate: 0 })
    logTerminal('cmd', `[>] LAUNCHING T1499 API REQUEST BURST: ${count} POST requests to ${burstEndpoint} against target [${targetSessionId.slice(0, 8)}]...`)

    let completed = 0
    try {
      await Promise.all(Array.from({ length: count }, async (_, index) => {
        const sentAt = new Date()
        let response
        try {
          response = await sendApiRequest({
            session_id: targetSessionId,
            endpoint: burstEndpoint,
            ip_address: burstIp,
            device_info: burstDevice,
          })
        } catch (error) {
          response = { ok: false, status: 'NETWORK ERROR', data: { detail: error.message } }
        }

        completed += 1
        const elapsedSeconds = Math.max((performance.now() - startedAt) / 1000, 0.001)
        setBurstProgress({ sent: count, completed, rate: completed / elapsedSeconds })
        const resultStatus = response.data?.status ? ` / ${response.data.status}` : ''
        logTerminal(response.ok ? 'info' : 'warn', `[API ${String(index + 1).padStart(String(count).length, '0')}/${count}] POST ${burstEndpoint} — ${sentAt.toLocaleTimeString()} — ${response.status}${resultStatus}`, response.data)
        if (response.data?.status) bumpRiskScore(response.data)
      }))
      setChain(c => ({ ...c, flood: true }))
      await loadSessions()
    } finally {
      setExecuting(false)
    }
  }

  // Generic technique runner (used by IP Change)
  async function runTechnique(name, fn, payload) {
    if (!targetSessionId) {
      logTerminal('error', '[-] Error: Select or create a target session before launching attack!')
      return null
    }
    setExecuting(true)
    logTerminal('cmd', `[>] LAUNCHING TECHNIQUE: ${name} against target [${targetSessionId.slice(0, 8)}]...`)
    let res = null
    try {
      res = await fn({ ...payload, session_id: targetSessionId })
      const isLockdown = res.status === 'LOCKDOWN' || res.final_status === 'LOCKDOWN'
      const isSuspicious = res.status === 'SUSPICIOUS'
      const isShadow = res.status === 'SHADOW'
      if (res.status) setTargetStatus(res.status)

      bumpRiskScore(res)
      setChain(c => ({ ...c, evade: true }))

      if (isLockdown) {
        logTerminal('error', `[🛑 TARGET LOCKED DOWN] Technique ${name} triggered automatic LOCKDOWN!`, res)
      } else if (isShadow) {
        logTerminal('warn', `[◐ TARGET CONTAINED IN SHADOW MODE] The identity change was uncertain, so the attacker is being served a sandbox: it looks like it works, nothing real moves, and every action is logged for your review (Active Sessions → Shadow queue).`, res)
      } else if (isSuspicious) {
        logTerminal('warn', `[⚠️ TARGET SUSPICIOUS] System flagged target session as SUSPICIOUS!`, res)
      } else {
        logTerminal('info', `[+] Attack telemetry accepted. Target Status: ${res.status || 'SAFE'}`, res)
      }
      await loadSessions()
    } catch (err) {
      logTerminal('error', `[-] Technique Execution Failed: ${err.message}`)
    } finally {
      setExecuting(false)
    }
    return res
  }

  const isLocked = targetStatus === 'LOCKDOWN' || targetStatus === 'locked'
  const target = sessions.find(s => s.session_id === targetSessionId)
  const tone = isLocked ? 'lock' : String(targetStatus).toLowerCase() === 'suspicious' ? 'sus' : 'safe'
  const visibleLogs = terminalLogs.filter(l => matchLevel(l.type, levelFilter))

  // kill chain: each stage lights up as the engagement progresses
  const stages = [
    { k: 'recon', label: 'Recon', sub: 'Target acquired', done: !!targetSessionId },
    { k: 'evade', label: 'Evasion', sub: 'T1090 identity churn', done: chain.evade },
    { k: 'flood', label: 'Impact', sub: 'T1499 request flood', done: chain.flood },
    { k: 'lock', label: 'Lockdown', sub: 'Defence triggers', done: isLocked },
  ]
  const nextStage = stages.findIndex(s => !s.done)

  function copyLog() {
    const text = visibleLogs.map(l => `[${l.time}] ${l.text}${l.data ? '\n' + JSON.stringify(l.data, null, 2) : ''}`).join('\n')
    navigator.clipboard?.writeText(text).catch(() => {})
  }

  const techs = [
    { id: 't1090', code: 'T1090', name: 'Proxy Hopping & IP Change', tactic: 'DEFENSE EVASION' },
    { id: 't1499', code: 'T1499', name: 'API Rate Burst / DoS', tactic: 'IMPACT' },
  ]

  return (
    <div className="atk">
      <header className="cm-page-head">
        <div>
          <div className="cm-eyebrow mono atk-eye"><span className="cm-dot" /> ATTACK SIMULATOR · RED TEAM</div>
          <h1>Attack Simulator</h1>
          <p>Manual Offensive Cyber Technique Suite • Step-by-Step Exploit Vector Testing</p>
        </div>
        <div className="atk-warn mono">⚠ authorized simulation — sandbox sessions only</div>
      </header>

      <div className="cm-seg atk-mode" role="tablist" aria-label="Attack mode">
        <button className={mode === 'manual' ? 'on' : ''} onClick={() => setMode('manual')}>MANUAL TECHNIQUES</button>
        <button className={mode === 'lab' ? 'on' : ''} onClick={() => setMode('lab')}>REALISTIC ATTACK LAB</button>
      </div>

      {mode === 'lab' ? <AttackLab /> : (<>

      {/* ───── Target & risk ───── */}
      <section className={`cm-card atk-target ${tone}`}>
        <div className="atk-target-main">
          <div className="atk-field">
            <label className="mono">TARGET SESSION</label>
            <select
              className="atk-select"
              value={targetSessionId}
              onChange={e => {
                setTargetSessionId(e.target.value)
                const match = sessions.find(s => s.session_id === e.target.value)
                if (match) setTargetStatus(match.status)
              }}
            >
              {sessions.length === 0 && <option value="">— No sessions. Spawn one →</option>}
              {sessions.map(s => (
                <option key={s.session_id} value={s.session_id}>
                  {s.user_label || s.session_id.slice(0, 8)} ({s.status}) - IP: {s.last_ip || 'unknown'}
                </option>
              ))}
            </select>
          </div>

          <div className="atk-id">
            <span className={`atk-avatar ${tone}`}>{((target?.user_label) || '?').slice(0, 1).toUpperCase()}</span>
            <div>
              <strong>{target?.user_label || 'No target selected'}</strong>
              <div className="mono atk-meta">{target ? `${target.session_id.slice(0, 8)} · ${target.last_ip || 'unknown IP'} · ${shortDevice(target.last_device)}` : '—'}</div>
            </div>
            <div className={`status-badge status-${targetStatus.toLowerCase()}`}>TARGET STATUS: {targetStatus}</div>
          </div>

          <div className="atk-actions">
            <button className="pro-btn" onClick={handleSpawnSandbox}>＋ SPAWN TARGET SANDBOX</button>
            <button className="pro-btn warn" onClick={handleTestProtectedAction} disabled={!targetSessionId}>🎯 TEST PROTECTED ACTION</button>
          </div>

          {isLocked && (
            <div className="unlock-strip atk-unlock">
              <span>🔐 Target session is LOCKED DOWN. Admin unlock required to re-enable testing.</span>
              <button className="pro-btn danger sm" onClick={handleUnlockTarget} disabled={unlocking}>
                {unlocking ? 'Unlocking…' : '🔓 ADMIN UNLOCK TARGET'}
              </button>
            </div>
          )}
        </div>

        <RiskGauge score={riskScore} max={LOCKDOWN_THRESHOLD} />
      </section>

      {/* kill chain */}
      <section className="cm-card atk-chain" aria-label="Engagement progress">
        {stages.map((s, i) => (
          <div key={s.k} className={`atk-stage${s.done ? ' done' : ''}${i === nextStage ? ' next' : ''}${s.k === 'lock' ? ' final' : ''}`}>
            <span className="atk-stage-n mono">{s.done ? '✓' : String(i + 1).padStart(2, '0')}</span>
            <div><b>{s.label}</b><em>{s.sub}</em></div>
          </div>
        ))}
      </section>

      {/* ───── Techniques + terminal ───── */}
      <div className="atk-grid">
        <section className="cm-card atk-deck">
          <div className="cm-card-head"><div className="cm-card-title"><i className="red" />Offensive Cyber Techniques (MITRE ATT&CK)</div></div>

          <div className="atk-techs">
            {techs.map(t => (
              <button key={t.id} className={`atk-tech${activeTab === t.id ? ' on' : ''}`} onClick={() => setActiveTab(t.id)}>
                <span className="mono">{t.code}</span>
                <b>{t.id === 't1090' ? 'T1090 IP Change' : 'T1499 API Request Attack'}</b>
                <em className="mono">{t.tactic}</em>
              </button>
            ))}
          </div>

          {activeTab === 't1090' && (
            <div className="atk-form">
              <div className="atk-form-title">T1090 • Proxy Hopping & IP Change</div>
              <p className="cm-muted">Instantly switches IP address or User-Agent headers during active session traffic to trip network anomaly detection. (Related ATT&CK: T1090 Proxy; session reuse maps to T1539 / T1550.004.)</p>
              <div className="atk-fields">
                <label><span className="mono">NEW SOURCE IP ADDRESS</span><input type="text" className="atk-input" value={churnIp} onChange={e => setChurnIp(e.target.value)} /></label>
                <label><span className="mono">NEW DEVICE USER-AGENT</span><input type="text" className="atk-input" value={churnDevice} onChange={e => setChurnDevice(e.target.value)} /></label>
              </div>
              <div className="atk-presets">
                <button className="preset-btn" onClick={() => { setChurnIp('185.220.101.5'); setChurnDevice('Tor-Exit-Node/7.0') }}>Tor Node (185.220.101.5)</button>
                <button className="preset-btn" onClick={() => { setChurnIp('95.216.14.88'); setChurnDevice('Python-urllib3/1.26') }}>Datacenter Proxy (95.216.14.88)</button>
              </div>
              <button
                className="atk-fire"
                disabled={executing || isLocked}
                onClick={() => runTechnique('T1090 Proxy Hopping', execIdentityChurn, { new_ip: churnIp, new_device: churnDevice })}
              >
                {executing ? 'SPOOFING IDENTITY…' : '⚡ SPOOF IDENTITY & TRANSMIT TRAFFIC'}
              </button>
            </div>
          )}

          {activeTab === 't1499' && (
            <div className="atk-form">
              <div className="atk-form-title">T1499 • API Rate Burst / Denial of Service</div>
              <p className="cm-muted">Rapidly floods API endpoints with high-volume requests to test short-window request burst detection rules. (Related ATT&CK: T1499 Endpoint DoS; login flooding maps to T1110.)</p>
              <div className="atk-fields">
                <label><span className="mono">REQUEST BURST COUNT</span><input type="number" className="atk-input" value={burstCount} onChange={e => setBurstCount(Number(e.target.value))} /></label>
                <label><span className="mono">TARGET ENDPOINT URL</span><input type="text" className="atk-input" value={burstEndpoint} onChange={e => setBurstEndpoint(e.target.value)} /></label>
                <label><span className="mono">SOURCE IP ADDRESS</span><input type="text" className="atk-input" value={burstIp} onChange={e => setBurstIp(e.target.value)} /></label>
                <label><span className="mono">DEVICE / USER-AGENT</span><input type="text" className="atk-input" value={burstDevice} onChange={e => setBurstDevice(e.target.value)} /></label>
              </div>
              <div className="atk-presets">
                <button className="preset-btn" onClick={() => { setBurstCount(25); setBurstEndpoint('/api/v1/user/export'); setBurstIp('45.134.26.7') }}>Preset: Data Exfil Flood</button>
                <button className="preset-btn" onClick={() => { setBurstCount(50); setBurstEndpoint('/api/v1/search'); setBurstIp('10.0.0.1') }}>Preset: Search DoS Flood</button>
              </div>
              <button className="atk-fire" disabled={executing || isLocked} onClick={handleApiRequestBurst}>
                {executing ? 'FLOODING API…' : '⚡ FIRE HIGH-FREQUENCY API REQUEST FLOOD'}
              </button>
              <div className="atk-burst" aria-live="polite">
                <div className="atk-burst-bar"><i style={{ width: `${Math.min(100, (burstProgress.completed / Math.max(1, burstProgress.sent || Number(burstCount) || 1)) * 100)}%` }} /></div>
                <div className="atk-burst-stats mono">
                  <span>REQUESTS <strong>{burstProgress.completed} / {burstProgress.sent || Math.max(1, Math.floor(Number(burstCount) || 1))}</strong></span>
                  <span>RATE <strong>{burstProgress.rate.toFixed(1)} req/s</strong></span>
                  <span>STATUS <strong>{executing ? 'IN FLIGHT' : burstProgress.completed ? 'COMPLETE' : 'READY'}</strong></span>
                </div>
              </div>
            </div>
          )}
        </section>

        <section className="cm-card atk-term">
          <div className="atk-term-bar">
            <div className="atk-dots"><i className="r" /><i className="y" /><i className="g" /></div>
            <span className="atk-term-title">ATTACKER CLI OUTPUT & RESPONSES</span>
            <div className="cm-seg atk-lv" aria-label="Filter log level">
              {LEVEL_FILTERS.map(([v, l]) => (
                <button key={v} className={`${levelFilter === v ? 'on' : ''} ${v === 'warn' ? 'sus' : v === 'error' ? 'lock' : ''}`} onClick={() => setLevelFilter(v)}>{l}</button>
              ))}
            </div>
            <span className="mono atk-count">{terminalLogs.length} events</span>
            <button className="pro-btn sm" onClick={copyLog} title="Copy visible output">COPY</button>
            <button className="pro-btn sm" onClick={() => setTerminalLogs([])}>CLEAR</button>
          </div>

          <div className="atk-term-body mono" ref={terminalBodyRef}>
            {visibleLogs.length === 0 ? (
              <div className="atk-term-empty">Terminal ready. Select an attack technique to fire.</div>
            ) : (
              visibleLogs.map(log => (
                <div key={log.id} className={`atk-line ${log.type}`}>
                  <span className="atk-ico">{LEVEL_ICON[log.type] || '·'}</span>
                  <span className="atk-time">{log.time}</span>
                  <span className="atk-text">{log.text}</span>
                  {log.data && (
                    <details className="atk-json"><summary>payload</summary><pre>{JSON.stringify(log.data, null, 2)}</pre></details>
                  )}
                </div>
              ))
            )}
          </div>

          <div className="atk-term-foot mono">
            <span className={`atk-prompt ${executing ? 'busy' : ''}`}>{executing ? '● executing…' : '❯ ready'}</span>
            <span>target {targetSessionId ? targetSessionId.slice(0, 8) : '—'}</span>
          </div>
        </section>
      </div>
      </>)}
    </div>
  )
}
