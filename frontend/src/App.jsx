import { useEffect, useMemo, useRef, useState } from 'react'
import Login from './components/Login'
import ProtectApp from './components/ProtectApp'
import EmailAnalysis from './components/EmailAnalysis'
import Landing from './components/Landing'
import Navbar, { TABS, openVaultApp } from './components/Navbar'
import Dashboard from './components/Dashboard'
import AttackerConsole from './components/AttackerConsole'
import LogsViewer from './components/LogsViewer'
import SessionsPanel from './components/SessionsPanel'

import UserPortal from './components/UserPortal'
import CybermindAI from './components/CybermindAI'
import IntroCinematic from './components/IntroCinematic'
import ThreatField from './components/ThreatField'
import CommandPalette from './components/CommandPalette'
import FeatureWorkspace from './components/FeatureWorkspace'
import { logout, getSessions } from './api'
import { connectLiveFeed } from './ws'

/**
 * The console is a flight through the neural network. Scrolling moves the 3D camera
 * (outside → orbit → shell → inside → core → exit). At each station only the feature's NAME appears,
 * with a glowing node. Click the node and that feature opens as a tab — assembled from separate pieces,
 * dismantled again when you go back.
 */
const STATIONS = {
  dashboard: { id: 'dashboard', name: 'Overview', line: 'Your security posture, live.', depth: 'OUTSIDE' },
  logs: { id: 'logs', name: 'Detections', line: 'Every decision, with the reason.', depth: 'ORBIT' },
  email: { id: 'email', name: 'Email Analysis', line: 'Read what the eye cannot.', depth: 'SHELL' },
  sessions: { id: 'sessions', name: 'Active Sessions', line: 'Contain. Release. Control.', depth: 'MEMBRANE' },
  attacker: { id: 'attacker', name: 'Attack Simulator', line: 'Test your defences safely.', depth: 'INSIDE' },
  integrate: { id: 'integrate', name: 'Integrations', line: 'Connect your app in minutes.', depth: 'CORE' },
  cybermind: { id: 'cybermind', name: 'Analyst Assistant', line: 'Ask the mind.', depth: 'EXIT' },
}
const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v))
const idxOf = (id) => TABS.findIndex(t => t.id === id)

export default function App() {
  const [introState, setIntroState] = useState('playing') // 'playing' | 'fading' | 'done'
  const [authed, setAuthed] = useState(false)
  const [entry, setEntry] = useState('landing') // 'landing' | 'login' (defender console)
  const [leaving, setLeaving] = useState(false)     // exit animation running before a page swap
  const [active, setActive] = useState(0) // station the camera is at (nav highlight / HUD)
  const [open, setOpen] = useState(null) // feature tab currently open (id) or null
  const [closing, setClosing] = useState(false)
  const [events, setEvents] = useState([])
  const [pulse, setPulse] = useState(0) // bumps on every live security event → ripples the 3D field
  const [alert, setAlert] = useState(null) // { id, text } lockdown banner
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [lockedSessions, setLockedSessions] = useState({}) // session_id -> {session_id, reason}
  const [logsRefreshKey, setLogsRefreshKey] = useState(0)
  const [sessionList, setSessionList] = useState([])   // current state of every monitored session (drives the global status)
  const disconnectRef = useRef(null)
  const alertTimer = useRef(null)
  const journey = useRef({ idx: 0, open: false, kick: 0 }) // read every frame by the 3D scene — no re-render
  const stationEls = useRef([])
  const hudFill = useRef(null)
  const openRef = useRef(null)
  const authedRef = useRef(false)
  const afterClose = useRef(null)
  openRef.current = open
  authedRef.current = authed

  const [hash, setHash] = useState(() => (typeof window !== 'undefined' ? window.location.hash : ''))

  useEffect(() => {
    const handleHashChange = () => setHash(window.location.hash)
    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [])

  // The live feed is admin-only, so it connects after sign-in and closes on sign-out
  useEffect(() => {
    if (!authed) return undefined
    disconnectRef.current = connectLiveFeed((msg) => {
      if (msg.type === 'security_event') {
        setEvents(prev => [{ ...msg, _t: Date.now() }, ...prev].slice(0, 200))
        setPulse(p => p + 1)
      }
      if (msg.type === 'lockdown') {
        setLockedSessions(prev => ({ ...prev, [msg.session_id]: { session_id: msg.session_id, reason: msg.reason } }))
        setLogsRefreshKey(k => k + 1)
        showAlert(`Session ${String(msg.session_id).slice(0, 8)} frozen by automated lockdown`)
      }
      if (msg.type === 'email_phishing') {
        setPulse(p => p + 1)
        showAlert(`${msg.verdict === 'PHISHING' ? 'Phishing email detected' : 'Suspicious email'}: ${String(msg.subject || '').slice(0, 70)}`, 'EMAIL')
      }
      if (msg.type === 'campaign_blocked') {
        setPulse(p => p + 1)
        showAlert(`Login attack campaign blocked: ${msg.attempts} attempts from ${msg.distinct_ips} IPs`, 'CAMPAIGN')
      }
      if (msg.type === 'decoy_touched') {
        showAlert('A decoy account was touched: an attacker is probing the login', 'DECOY')
      }
      if (msg.type === 'unlocked' || msg.type === 'step_up_cleared') {
        setLockedSessions(prev => {
          const next = { ...prev }
          delete next[msg.session_id]
          return next
        })
        setLogsRefreshKey(k => k + 1)
      }
    })
    return () => { disconnectRef.current && disconnectRef.current(); clearTimeout(alertTimer.current) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authed])

  function showAlert(text, label = 'LOCKDOWN') {
    setAlert({ id: Date.now(), text, label })
    clearTimeout(alertTimer.current)
    alertTimer.current = setTimeout(() => setAlert(null), 6500)
  }

  // If the server says our token expired or was revoked, sign out cleanly
  useEffect(() => {
    const onExpired = () => { if (authedRef.current) handleLogout() }
    window.addEventListener('cm-session-expired', onExpired)
    return () => window.removeEventListener('cm-session-expired', onExpired)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // play the exit animation, swap the page, then let the new page animate in
  function swapPage(fn) {
    if (leaving) return
    setLeaving(true)
    setTimeout(() => { fn(); setLeaving(false) }, 480)
  }
  const goConsole = () => swapPage(() => setEntry('login'))
  const goHome = () => swapPage(() => setEntry('landing'))
  const goDemo = () => swapPage(() => { window.location.hash = '#user-portal' })

  function handleLoginSuccess() {
    setAuthed(true)
    setActive(0); setOpen(null); setClosing(false)
    journey.current.idx = 0
    window.scrollTo(0, 0)
  }

  function handleLogout() {
    logout()
    setAuthed(false); setEntry('landing')
    setActive(0); setOpen(null); setClosing(false)
    journey.current.idx = 0
  }

  // The global status follows what sessions are in RIGHT NOW (not the history of past events), so clearing or
  // unlocking sessions brings it back down. Refreshes every few seconds and whenever a live event arrives.
  const loadSessionsRef = useRef(null)
  useEffect(() => {
    if (!authed) { setSessionList([]); loadSessionsRef.current = null; return undefined }
    let alive = true
    const load = async () => { try { const l = await getSessions(); if (alive) setSessionList(Array.isArray(l) ? l : []) } catch { /* ignore */ } }
    loadSessionsRef.current = load
    load()
    const t = setInterval(load, 4000)
    return () => { alive = false; clearInterval(t); loadSessionsRef.current = null }
  }, [authed])
  // a live event or an unlock/clear refreshes straight away (throttled so a flood of events is one fetch)
  useEffect(() => {
    const t = setTimeout(() => loadSessionsRef.current && loadSessionsRef.current(), 600)
    return () => clearTimeout(t)
  }, [pulse, logsRefreshKey])

  const lockedIds = new Set(Object.keys(lockedSessions))
  const threat = useMemo(
    () => (sessionList.some(x => x.status === 'locked') ? 'LOCKDOWN' : sessionList.some(x => x.status === 'suspicious') ? 'SUSPICIOUS' : 'SAFE'),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sessionList],
  )
  const standalonePortal = hash === '#user-portal'

  // dark console look everywhere except the standalone VaultApp portal
  useEffect(() => {
    document.body.classList.toggle('cm-body', !standalonePortal)
    return () => document.body.classList.remove('cm-body')
  }, [standalonePortal])

  // while a feature is open the page behind it must not scroll
  useEffect(() => {
    journey.current.open = !!open
    document.body.style.overflow = open ? 'hidden' : ''
    document.body.classList.toggle('cm-open', !!open)
    return () => { document.body.style.overflow = ''; document.body.classList.remove('cm-open') }
  }, [open])

  // ---- scroll → journey progress (continuous station index) + per-station 3D parallax ----
  useEffect(() => {
    if (!authed || introState === 'playing') return
    let raf = 0, lastActive = -1
    const tick = () => {
      raf = requestAnimationFrame(tick)
      const vh = window.innerHeight
      const els = stationEls.current
      let idx = 0
      els.forEach((el, i) => {
        if (!el) return
        const r = el.getBoundingClientRect()
        if (r.top <= 2) idx = i + clamp(-r.top / Math.max(1, r.height - vh * 0.35))
        const head = el.querySelector('.cm-station-head')
        if (head) {
          const hr = head.getBoundingClientRect()
          const d = clamp((hr.top + hr.height / 2 - vh / 2) / vh, -1, 1)
          head.style.setProperty('--d', d.toFixed(3)); head.style.setProperty('--ad', Math.abs(d).toFixed(3))
          const live = Math.abs(d) < 0.55 ? '1' : '0'
          if (head.dataset.live !== live) head.dataset.live = live
        }
      })
      idx = clamp(idx, 0, Math.max(0, els.length - 1))
      journey.current.idx = idx
      if (hudFill.current) hudFill.current.style.setProperty('--p', (idx / Math.max(1, els.length - 1)).toFixed(4))
      const a = Math.min(els.length - 1, Math.floor(idx + 0.4))
      if (a !== lastActive) { lastActive = a; setActive(a) }
    }
    tick()
    return () => cancelAnimationFrame(raf)
  }, [authed, introState])

  // ---- open / close / switch a feature tab ----
  function openFeature(id) {
    if (!STATIONS[id]) return
    journey.current.kick = 0.9
    setClosing(false); setOpen(id)
  }
  function closeFeature(next = null) {
    if (!openRef.current) return
    afterClose.current = next
    setClosing(true)
  }
  function onClosed() {
    const next = afterClose.current
    afterClose.current = null
    setClosing(false)
    journey.current.kick = 0.7
    if (next) {
      const el = stationEls.current[idxOf(next)]
      if (el) window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY, behavior: 'auto' })
      setOpen(next)
    } else {
      setOpen(null)
    }
  }
  // fly to a station (scroll), then open it
  function goTo(id, andOpen = true) {
    if (openRef.current) { if (openRef.current !== id) closeFeature(id); return }
    const el = stationEls.current[idxOf(id)]
    if (!el) return
    window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY, behavior: 'smooth' })
    if (andOpen) setTimeout(() => { if (!openRef.current) openFeature(id) }, 1500)
  }
  const api = useRef({}); api.current = { goTo, openFeature, closeFeature }

  // keyboard: Ctrl/Cmd+K palette, 1-6 fly to a feature, Enter opens the current station, Esc goes back
  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k' && authed) { e.preventDefault(); setPaletteOpen(o => !o); return }
      if (!authed || paletteOpen) return
      if (e.key === 'Escape' && openRef.current) { api.current.closeFeature(); return }
      const tag = (e.target.tagName || '').toLowerCase()
      if (e.ctrlKey || e.metaKey || e.altKey || tag === 'input' || tag === 'textarea' || tag === 'select') return
      const tab = TABS.find(t => t.key === e.key)
      if (tab) { api.current.goTo(tab.id, true); return }
      if (e.key === 'Enter' && !openRef.current) api.current.openFeature(TABS[Math.min(TABS.length - 1, Math.round(journey.current.idx))].id)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [authed, paletteOpen])

  const paletteItems = useMemo(() => [
    ...TABS.map(t => ({ id: t.id, label: `Open ${t.label}`, hint: `key ${t.key}`, run: () => api.current.goTo(t.id, true) })),
    { id: 'vault', label: 'Open VaultApp demo (new window)', hint: 'customer side', run: openVaultApp },
    { id: 'logout', label: 'Log out', hint: 'end session', run: handleLogout },
  ], [])

  if (standalonePortal) {
    return <div className="cm-page-enter"><UserPortal /></div>
  }

  const featureBody = {
    dashboard: <Dashboard events={events} lockedSessionIds={lockedIds} setView={(id) => api.current.goTo(id, true)} pulse={pulse} />,
    attacker: <AttackerConsole />,
    logs: <LogsViewer refreshKey={logsRefreshKey} />,
    email: <EmailAnalysis onAnalyzed={() => setPulse(p => p + 1)} />,
    sessions: (
      <SessionsPanel
        refreshKey={logsRefreshKey}
        onUnlocked={(sid) => setLockedSessions(prev => {
          const next = { ...prev }
          delete next[sid]
          return next
        })}
      />
    ),
    cybermind: <CybermindAI />,
    integrate: <ProtectApp />,
  }

  // tiny live readouts shown under a station name
  const meta = {
    dashboard: threat === 'LOCKDOWN' ? 'LOCKDOWN ACTIVE' : threat === 'SUSPICIOUS' ? 'ELEVATED WATCH' : 'SYSTEM SECURE',
    sessions: lockedIds.size ? `${lockedIds.size} IN LOCKDOWN` : null,
  }

  const openIdx = open ? idxOf(open) : -1

  return (
    <>
      {/* Cinematic 3D intro — plays on every load, then hands over to the admin login */}
      {introState !== 'done' && (
        <IntroCinematic
          onFadeStart={() => setIntroState('fading')}
          onComplete={() => setIntroState('done')}
        />
      )}

      {/* Living 3D neural network — fixed behind everything; in the console its camera is driven by scroll */}
      {introState !== 'playing' && (
        <ThreatField
          threat={authed ? threat : 'SAFE'} pulse={pulse} mode={authed ? 'ambient' : 'hero'}
          journey={journey}
        />
      )}

      {/* Main Screen — mounts underneath and is revealed as the intro fades */}
      {introState !== 'playing' && (
        <div className={introState === 'fading' ? 'cm-reveal' : ''}>
          {!authed ? (
            <div className={`cm-app cm-page ${leaving ? 'cm-page-exit' : 'cm-page-enter'}`} data-threat="SAFE" key={entry}>
              {entry === 'landing'
                ? <Landing onConsole={goConsole} onVault={goDemo} />
                : <Login onSuccess={handleLoginSuccess} onBack={goHome} />}
            </div>
          ) : (
            <div className="cm-shell">
              <div className="cm-app cm-rail-wrap" data-threat={threat}>
                <Navbar
                  view={TABS[open ? openIdx : active]?.id}
                  setView={(id) => goTo(id, true)}
                  onLogout={handleLogout} threat={threat} onOpenPalette={() => setPaletteOpen(true)}
                />
              </div>

              <div className="cm-app cm-main cm-journey" data-threat={threat}>
                {TABS.map((t, i) => {
                  const st = STATIONS[t.id]
                  return (
                    <section key={t.id} id={t.id} className={`cm-station st-${t.id}`} ref={el => { stationEls.current[i] = el }}>
                      <header className="cm-station-head" data-live="0">
                        <b className="mono">{String(i + 1).padStart(2, '0')} / {String(TABS.length).padStart(2, '0')} · {st.depth}</b>
                        <h2>{st.name}</h2>
                        <p>{st.line}</p>
                        {meta[t.id] && <span className={`cm-station-meta mono${t.id === 'sessions' ? ' red' : ''}`}>{meta[t.id]}</span>}
                        <button className="cm-node" onClick={() => openFeature(t.id)} aria-label={`Open ${st.name}`}>
                          <i className="cm-node-orb"><b /><u /><s /></i>
                          <span className="mono">ENTER {st.name.toUpperCase()}</span>
                        </button>
                        {i === 0 && <div className="cm-scroll-hint mono">SCROLL TO DIVE ↓</div>}
                      </header>
                    </section>
                  )
                })}
                <div className="cm-end mono">— you have exited the network · scroll up to dive back in —</div>
              </div>

              {/* depth HUD */}
              <aside className="cm-hud mono" aria-hidden="true">
                <div className="cm-hud-track"><i ref={hudFill} /></div>
                <ol>
                  {TABS.map((t, i) => (
                    <li key={t.id} className={i === active ? 'on' : i < active ? 'past' : ''}><span>{STATIONS[t.id].depth}</span></li>
                  ))}
                </ol>
              </aside>

              {/* the opened feature tab — assembles from pieces, dismantles on close */}
              {open && (
                <div className="cm-app" data-threat={threat}>
                  <FeatureWorkspace
                    key={open}
                    station={STATIONS[open]} index={openIdx} total={TABS.length}
                    closing={closing} onClosed={onClosed}
                    onClose={() => closeFeature()}
                    onPrev={() => closeFeature(TABS[openIdx - 1]?.id)}
                    onNext={() => closeFeature(TABS[openIdx + 1]?.id)}
                  >
                    {featureBody[open]}
                  </FeatureWorkspace>
                </div>
              )}

              {alert && (
                <div className="cm-app" data-threat={threat}>
                  <div className="cm-alert" key={alert.id} role="alert">
                    <span className="cm-alert-ico">⚠</span>
                    <b>{alert.label || 'LOCKDOWN'}</b><span>{alert.text}</span>
                    <button onClick={() => setAlert(null)} aria-label="Dismiss">✕</button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <div className="cm-app" data-threat={threat}>
        <CommandPalette open={paletteOpen && authed} onClose={() => setPaletteOpen(false)} items={paletteItems} />
      </div>
    </>
  )
}
