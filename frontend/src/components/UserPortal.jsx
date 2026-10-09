import { useEffect, useMemo, useRef, useState } from "react"
import {
  getUserStatus, sendUserBehavior, fetchClientIp,
  bankRegister, bankLogin, bankAccount, bankTransfer, bankStepUp,
} from "../api"
import "./vault.css"

const deviceInfo = () => navigator.userAgent.slice(0, 240)
const money = (n) => (n < 0 ? "-" : n > 0 ? "+" : "") + "$" + Math.abs(n).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })
const standardDeviation = values => {
  if (values.length < 2) return 0
  const average = values.reduce((sum, value) => sum + value, 0) / values.length
  return Math.sqrt(values.reduce((sum, value) => sum + (value - average) ** 2, 0) / values.length)
}
const typingSnapshot = (times, intervals, now = Date.now()) => {
  const recentTimes = times.filter(time => now - time <= 10000)
  const first = recentTimes[0] ?? now
  const activeMinutes = Math.max((now - first) / 60000, 1 / 60)
  const recentIntervals = intervals.slice(-Math.max(recentTimes.length - 1, 0))
  const average = recentIntervals.length ? recentIntervals.reduce((s, v) => s + v, 0) / recentIntervals.length : 0
  return { cpm: recentTimes.length / activeMinutes, avg: average, std: standardDeviation(recentIntervals) }
}

const STORAGE_KEY = "vaultapp_session"
const CATEGORY_ICON = { Income: "💼", Housing: "🏠", Groceries: "🛒", Utilities: "⚡", Investment: "📈", Transfer: "↗" }

const FROST = [
  { top: "12%", left: "8%", dur: "4.2s", delay: "0s", sym: "❄" }, { top: "22%", left: "84%", dur: "5.1s", delay: "0.8s", sym: "✦" },
  { top: "58%", left: "11%", dur: "6.0s", delay: "1.4s", sym: "❄" }, { top: "74%", left: "82%", dur: "4.6s", delay: "0.3s", sym: "✦" },
  { top: "38%", left: "91%", dur: "5.5s", delay: "2.0s", sym: "❄" }, { top: "82%", left: "22%", dur: "4.4s", delay: "1.1s", sym: "✦" },
]

function FreezeOverlay({ sessionId, status, reason, onLogout }) {
  if (status !== "LOCKDOWN") return null
  const reasons = Array.isArray(reason) ? reason : []
  return (
    <div className="vault-freeze-overlay" role="alertdialog" aria-label="Session locked">
      <div className="vault-ice-edge-top" /><div className="vault-ice-edge-bottom" />
      {FROST.map((p, i) => (
        <span key={i} className="vault-frost-particle" style={{ top: p.top, left: p.left, animationDuration: p.dur, animationDelay: p.delay }} aria-hidden="true">{p.sym}</span>
      ))}
      <div className="vault-freeze-card">
        <div className="vault-freeze-icon-wrap">🔐</div>
        <p className="vault-freeze-title">Security alert</p>
        <h2 className="vault-freeze-headline">Session frozen</h2>
        <p className="vault-freeze-desc">
          Unusual activity was detected, so this session was frozen automatically by <strong style={{ color: "#a8d4f5" }}>CYBERMIND AI</strong>.
          Your money is safe and all account actions are paused.
        </p>
        {sessionId && <div className="vault-freeze-session">🆔 Reference: <span>{sessionId.slice(0, 8).toUpperCase()}</span></div>}
        {reasons.length > 0 && <div className="vault-freeze-reasons">{reasons.map((r, i) => <span key={i} className="vault-freeze-reason-tag">{String(r).replace(/_/g, " ")}</span>)}</div>}
        <div className="vault-freeze-divider" />
        <p className="vault-freeze-admin-note">🛡 Contact the bank's security team to restore access. Only an administrator can unlock this session.</p>
        <div style={{ marginTop: 16, textAlign: "center" }}>
          <button type="button" onClick={onLogout} className="vault-logout-btn" style={{ display: "inline-flex", padding: "8px 18px", borderRadius: 8, cursor: "pointer" }}>
            ⎋ <span>Sign out</span>
          </button>
        </div>
      </div>
    </div>
  )
}

const NAV_ITEMS = [
  { id: "Accounts", icon: "⬡", label: "Accounts" },
  { id: "Transfer", icon: "↗", label: "Transfer" },
  { id: "Security", icon: "🛡", label: "Security" },
  { id: "Profile", icon: "⚙", label: "Profile" },
]

export default function UserPortal() {
  // ---- session / account ----
  const [sessionId, setSessionId] = useState(null)
  const [profile, setProfile] = useState(null)
  const [transactions, setTransactions] = useState([])
  const [status, setStatus] = useState("SAFE")
  const [lockdownReason, setLockdownReason] = useState([])
  const [ip, setIp] = useState(() => { try { return window.localStorage.getItem("vault_public_ip") || "Detecting…" } catch { return "Detecting…" } })
  const [page, setPage] = useState("Accounts")
  const [booting, setBooting] = useState(true)

  // ---- auth form ----
  const [mode, setMode] = useState("signin")             // signin | register
  const [form, setForm] = useState({ username: "", full_name: "", password: "" })
  const [authMsg, setAuthMsg] = useState({ kind: "", text: "" })
  const [busy, setBusy] = useState(false)

  // ---- transfer / step-up ----
  const [tx, setTx] = useState({ recipient: "", amount: "", memo: "" })
  const [review, setReview] = useState(false)
  const [txMsg, setTxMsg] = useState({ kind: "", text: "" })
  const [stepOpen, setStepOpen] = useState(false)
  const [stepPw, setStepPw] = useState("")
  const [stepMsg, setStepMsg] = useState("")
  const retryAfterStepUp = useRef(false)

  // ---- behaviour capture (what CYBERMIND learns from) ----
  const keyTimes = useRef([])
  const intervals = useRef([])
  const clicks = useRef([])
  const moves = useRef([])
  const startedAt = useRef(Date.now())
  const [tick, setTick] = useState(0)

  const metrics = useMemo(() => {
    const typing = typingSnapshot(keyTimes.current, intervals.current)
    const movement = moves.current
    const entropy = movement.length < 2 ? 0 : Math.min(1, new Set(movement.map(p => `${Math.round(p.x / 40)}:${Math.round(p.y / 40)}`)).size / movement.length)
    return { ...typing, entropy, clickRate: clicks.current.filter(t => Date.now() - t < 60000).length }
  }, [status, page, tick])

  const recordKey = () => {
    const now = Date.now(); const prev = keyTimes.current.at(-1)
    if (prev) intervals.current = [...intervals.current.slice(-99), now - prev]
    keyTimes.current = [...keyTimes.current.slice(-99), now]; setTick(t => t + 1)
  }
  const resetBehaviour = () => { keyTimes.current = []; intervals.current = []; clicks.current = []; moves.current = []; startedAt.current = Date.now() }

  useEffect(() => {
    const detect = async () => { try { const d = await fetchClientIp(); if (d) setIp(d) } catch { setIp(p => (p === "Detecting…" ? "127.0.0.1" : p)) } }
    detect()
    const t = setInterval(detect, 8000)
    const mm = e => { moves.current = [...moves.current.slice(-199), { x: e.clientX, y: e.clientY }] }
    const mc = () => { clicks.current = [...clicks.current.slice(-99), Date.now()] }
    const paste = e => {
      const n = Math.min(Math.max(e.clipboardData?.getData("text")?.length || 1, 1), 100)
      intervals.current = [...intervals.current.slice(-(100 - n)), ...Array(n).fill(1)]; setTick(x => x + 1)
    }
    document.addEventListener("mousemove", mm); document.addEventListener("click", mc); document.addEventListener("paste", paste)
    return () => { clearInterval(t); document.removeEventListener("mousemove", mm); document.removeEventListener("click", mc); document.removeEventListener("paste", paste) }
  }, [])

  // restore a previous session if the server still knows it
  useEffect(() => {
    let alive = true
    ;(async () => {
      try {
        const saved = JSON.parse(window.localStorage.getItem(STORAGE_KEY) || "null")
        if (saved?.sessionId) {
          const r = await bankAccount(saved.sessionId)
          if (alive && r.ok) {
            setSessionId(saved.sessionId); setProfile(r.data.profile); setTransactions(r.data.transactions)
            setStatus(r.data.locked ? "LOCKDOWN" : r.data.step_up_required ? "SUSPICIOUS" : "SAFE"); startedAt.current = Date.now()
          } else window.localStorage.removeItem(STORAGE_KEY)
        }
      } catch {}
      if (alive) setBooting(false)
    })()
    return () => { alive = false }
  }, [])

  useEffect(() => {
    try { if (sessionId) window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ sessionId })); else window.localStorage.removeItem(STORAGE_KEY) } catch {}
  }, [sessionId])

  // server-side status (an admin may unlock, or CYBERMIND may freeze, at any time)
  useEffect(() => {
    if (!sessionId) return
    let cancelled = false
    const poll = async () => {
      try {
        const cur = await getUserStatus(sessionId)
        if (cancelled) return
        setStatus(cur.status)
        if (cur.last_ip) setIp(cur.last_ip)
      } catch {}
    }
    poll()
    const t = setInterval(poll, 3000)
    return () => { cancelled = true; clearInterval(t) }
  }, [sessionId])

  // behaviour telemetry to CYBERMIND
  useEffect(() => {
    if (!sessionId || status === "LOCKDOWN") return
    const t = setInterval(async () => {
      const now = Date.now()
      const typing = typingSnapshot(keyTimes.current, intervals.current, now)
      const mv = moves.current
      const entropy = mv.length < 2 ? 0 : Math.min(1, new Set(mv.map(p => `${Math.round(p.x / 40)}:${Math.round(p.y / 40)}`)).size / mv.length)
      const r = await sendUserBehavior({
        session_id: sessionId, event_type: "behavior", ip_address: ip === "Unavailable" || ip === "Detecting…" ? null : ip,
        device_info: deviceInfo(), keystroke_avg_interval_ms: typing.avg, keystroke_std_interval_ms: typing.std, typing_speed_cpm: typing.cpm,
        mouse_click_rate: clicks.current.filter(c => now - c < 60000).length, mouse_move_entropy: entropy, session_duration_sec: (now - startedAt.current) / 1000,
      })
      if (r.data.status) setStatus(r.data.status)
      if (r.status === 423) setStatus("LOCKDOWN")
      if (r.data.reason) setLockdownReason(r.data.reason)
    }, 2000)
    return () => clearInterval(t)
  }, [sessionId, ip, status])

  // ---- actions ----
  const setField = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }))

  async function submitAuth(e) {
    e.preventDefault(); setBusy(true); setAuthMsg({ kind: "", text: "" })
    try {
      if (mode === "register") {
        const r = await bankRegister(form.username, form.full_name, form.password)
        if (!r.ok) { setAuthMsg({ kind: "err", text: r.detail || "Could not create the account" }); return }
        setAuthMsg({ kind: "ok", text: "Account created. Sign in to continue." }); setMode("signin"); setForm(f => ({ ...f, password: "" })); return
      }
      const r = await bankLogin(form.username, form.password, deviceInfo())
      if (!r.ok) { setAuthMsg({ kind: "err", text: r.detail || "Sign-in failed" }); return }
      const acc = await bankAccount(r.data.session_id)
      resetBehaviour()
      setSessionId(r.data.session_id); setProfile(r.data.profile); setTransactions(acc.ok ? acc.data.transactions : [])
      setStatus(r.data.step_up_required ? "SUSPICIOUS" : "SAFE"); setLockdownReason([]); setPage("Accounts"); setForm(f => ({ ...f, password: "" }))
    } finally { setBusy(false) }
  }

  function signOut() {
    setSessionId(null); setProfile(null); setTransactions([]); setStatus("SAFE"); setLockdownReason([]); setPage("Accounts")
    setTx({ recipient: "", amount: "", memo: "" }); setReview(false); setTxMsg({ kind: "", text: "" })
  }

  async function sendTransfer() {
    setTxMsg({ kind: "", text: "" }); setBusy(true)
    try {
      const r = await bankTransfer(sessionId, tx.recipient, parseFloat(tx.amount), tx.memo)
      if (r.status === 428) { retryAfterStepUp.current = true; setStepOpen(true); setStatus("SUSPICIOUS"); return }
      if (r.status === 423) { setStatus("LOCKDOWN"); return }
      if (!r.ok) { setTxMsg({ kind: "err", text: r.detail || "Transfer failed" }); setReview(false); return }
      setProfile(p => ({ ...p, balance: r.data.balance })); setTransactions(r.data.transactions)
      setTxMsg({ kind: "ok", text: `Sent ${money(-Math.abs(parseFloat(tx.amount))).replace("-", "")} to ${tx.recipient}.` })
      setTx({ recipient: "", amount: "", memo: "" }); setReview(false)
    } finally { setBusy(false) }
  }

  async function verifyStepUp(e) {
    e.preventDefault(); setStepMsg(""); setBusy(true)
    try {
      const r = await bankStepUp(sessionId, stepPw)
      if (!r.ok) { setStepMsg(r.detail || "Verification failed"); return }
      setStepPw(""); setStepOpen(false); setStatus("SAFE")
      if (retryAfterStepUp.current) { retryAfterStepUp.current = false; await sendTransfer() }
    } finally { setBusy(false) }
  }

  const amountNum = parseFloat(tx.amount)
  const amountOk = Number.isFinite(amountNum) && amountNum > 0
  const statusKey = (status || "SAFE").toLowerCase()
  const statusLabel = status === "LOCKDOWN" ? "FROZEN" : status === "SUSPICIOUS" ? "VERIFY" : "PROTECTED"

  // ================================================================ signed-out
  if (!sessionId) {
    return (
      <div className="vault-root">
        <section className="vault-login">
          <form className="vault-login-card" onSubmit={submitAuth}>
            <div className="vault-login-logo-wrap">
              <div className="vault-login-shield">🏦</div>
              <h1>VaultApp Banking</h1>
              <p>{mode === "signin" ? "Sign in to your accounts" : "Open a demo account in seconds"}</p>
            </div>
            <div className="vault-tabs" role="tablist">
              <button type="button" role="tab" aria-selected={mode === "signin"} className={mode === "signin" ? "on" : ""} onClick={() => { setMode("signin"); setAuthMsg({ kind: "", text: "" }) }}>Sign in</button>
              <button type="button" role="tab" aria-selected={mode === "register"} className={mode === "register" ? "on" : ""} onClick={() => { setMode("register"); setAuthMsg({ kind: "", text: "" }) }}>Open account</button>
            </div>
            {mode === "register" && (
              <div className="vault-form-group">
                <label htmlFor="vault-fullname">Full name</label>
                <input id="vault-fullname" value={form.full_name} onChange={setField("full_name")} onKeyDown={recordKey} autoComplete="name" required minLength={2} />
              </div>
            )}
            <div className="vault-form-group">
              <label htmlFor="vault-username">Username</label>
              <input id="vault-username" autoFocus value={form.username} onChange={setField("username")} onKeyDown={recordKey} autoComplete="username" required />
            </div>
            <div className="vault-form-group">
              <label htmlFor="vault-password">Password</label>
              <input id="vault-password" type="password" value={form.password} onChange={setField("password")} onKeyDown={recordKey}
                autoComplete={mode === "signin" ? "current-password" : "new-password"} required minLength={mode === "register" ? 8 : 1} placeholder={mode === "register" ? "At least 8 characters" : ""} />
            </div>
            {authMsg.text && <div className={authMsg.kind === "ok" ? "vault-ok-msg" : "vault-error-msg"}>{authMsg.kind === "ok" ? "✓" : "⚠"} {authMsg.text}</div>}
            <button className="vault-primary" type="submit" id="vault-signin-btn" disabled={busy || booting}>
              {busy ? "Please wait…" : mode === "signin" ? "🔐 Secure sign in" : "Create account"}
            </button>
            <div className="vault-sentinel-badge">🛡 Sign-ins are protected by <span>CYBERMIND AI</span></div>
            <div style={{ textAlign: "center", marginTop: 14 }}>
              <a href="/" className="vault-back" onClick={(e) => {
                e.preventDefault()
                const root = e.currentTarget.closest(".vault-root")
                if (root) root.classList.add("cm-page-exit")
                setTimeout(() => { window.scrollTo(0, 0); window.location.hash = "" }, 480)
              }}>← Back to CYBERMIND home</a>
            </div>
          </form>
        </section>
      </div>
    )
  }

  // ================================================================ signed-in
  return (
    <div className="vault-root">
      <div className="vault-app">
        <aside className="vault-side">
          <div className="vault-logo">
            <div className="vault-logo-icon">🏦</div>
            <div className="vault-logo-text"><strong>VaultApp</strong><small>Banking</small></div>
          </div>
          <p className="vault-nav-label">Menu</p>
          {NAV_ITEMS.map(item => (
            <button key={item.id} className={`vault-nav-btn${page === item.id ? " active" : ""}`} onClick={() => setPage(item.id)} id={`vault-nav-${item.id.toLowerCase()}`}>
              <span className="nav-icon">{item.icon}</span><span className="nav-label">{item.label}</span>
            </button>
          ))}
          <div className="vault-user-chip">
            <div className="vault-user-info">
              <div className="vault-avatar">{(profile?.full_name || "U")[0].toUpperCase()}</div>
              <div className="vault-user-meta">
                <span className="vault-user-name">{profile?.full_name}</span>
                <span className="vault-session-mini">@{profile?.username}</span>
              </div>
            </div>
            <button className="vault-logout-btn" onClick={signOut} id="vault-logout-btn">⎋ <span>Sign out</span></button>
          </div>
        </aside>

        <main className="vault-main">
          <div className="vault-page-header">
            <div>
              <p className="vault-page-eyebrow">Personal banking</p>
              <h1 className="vault-page-title">{page}</h1>
            </div>
            <div className={`vault-status-pill ${statusKey}`}><div className="vault-status-pip" />{statusLabel}</div>
          </div>

          {status === "SUSPICIOUS" && (
            <div className="vault-banner" role="status">
              <span>⚠ We noticed unusual activity on this session. Verify it is you before moving money.</span>
              <button type="button" onClick={() => { retryAfterStepUp.current = false; setStepOpen(true) }}>Verify now</button>
            </div>
          )}

          {page === "Accounts" && (
            <div className="vault-page" key="accounts">
              <div className="vault-balance-card">
                <p className="vault-balance-label">Available balance</p>
                <div className="vault-balance-amount"><sup>$</sup>{Math.floor(profile.balance).toLocaleString("en-US")}<span style={{ fontSize: 28, opacity: 0.85 }}>.{String(Math.round((profile.balance % 1) * 100)).padStart(2, "0")}</span></div>
                <div className="vault-balance-meta">
                  <div className="vault-balance-chip">💳 {profile.account_no}</div>
                  <div className="vault-balance-chip">Everyday account</div>
                  <div className="vault-sentinel-active-badge"><div className="vault-sentinel-dot" />Protected by CYBERMIND</div>
                </div>
              </div>
              <div className="vault-section-head">
                <span className="vault-section-title">Recent activity</span>
                <button className="vault-section-link" onClick={() => setPage("Transfer")}>New transfer →</button>
              </div>
              <div className="vault-transactions">
                {transactions.map(t => (
                  <div key={t.id} className="vault-tx-row">
                    <div className="vault-tx-icon">{CATEGORY_ICON[t.category] || "•"}</div>
                    <div className="vault-tx-info"><div className="vault-tx-name">{t.name}</div><div className="vault-tx-date">{t.date}{t.memo ? ` · ${t.memo}` : ""}</div></div>
                    <div><div className={`vault-tx-amount ${t.amount < 0 ? "debit" : "credit"}`}>{money(t.amount)}</div><div className="vault-tx-category">{t.category}</div></div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {page === "Transfer" && (
            <div className="vault-page" key="transfer">
              <div className="vault-form-card">
                {!review ? (
                  <form onSubmit={(e) => { e.preventDefault(); setTxMsg({ kind: "", text: "" }); if (amountOk) setReview(true) }}>
                    <div className="vault-form-group"><label htmlFor="vault-recipient">Recipient</label>
                      <input id="vault-recipient" value={tx.recipient} onChange={e => setTx(t => ({ ...t, recipient: e.target.value }))} onKeyDown={recordKey} placeholder="Name or account number" required minLength={2} /></div>
                    <div className="vault-form-group"><label htmlFor="vault-amount">Amount (USD)</label>
                      <input id="vault-amount" value={tx.amount} onChange={e => setTx(t => ({ ...t, amount: e.target.value }))} onKeyDown={recordKey} inputMode="decimal" placeholder="0.00" required /></div>
                    <div className="vault-form-group"><label htmlFor="vault-memo">Memo (optional)</label>
                      <input id="vault-memo" value={tx.memo} onChange={e => setTx(t => ({ ...t, memo: e.target.value }))} onKeyDown={recordKey} maxLength={140} placeholder="What is this payment for?" /></div>
                    {txMsg.text && <div className={txMsg.kind === "ok" ? "vault-ok-msg" : "vault-error-msg"}>{txMsg.kind === "ok" ? "✓" : "⚠"} {txMsg.text}</div>}
                    <button className="vault-review-btn" type="submit" id="vault-review-transfer" disabled={!amountOk}>↗ Review transfer</button>
                  </form>
                ) : (
                  <div>
                    <p className="vault-panel-title">Confirm transfer</p>
                    {[["To", tx.recipient], ["Amount", "$" + amountNum.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })], ["Memo", tx.memo || "—"], ["From", `Everyday ${profile.account_no}`]].map(([k, v]) => (
                      <div key={k} className="vault-metric-row"><span className="vault-metric-key">{k}</span><span className="vault-metric-val">{v}</span></div>
                    ))}
                    {txMsg.text && <div className="vault-error-msg" style={{ marginTop: 12 }}>⚠ {txMsg.text}</div>}
                    <div className="vault-btn-row">
                      <button type="button" className="vault-ghost" onClick={() => setReview(false)} disabled={busy}>Back</button>
                      <button type="button" className="vault-review-btn" onClick={sendTransfer} disabled={busy} id="vault-confirm-transfer">{busy ? "Sending…" : "Confirm and send"}</button>
                    </div>
                  </div>
                )}
              </div>
              <div className="vault-security-bar" style={{ marginTop: 20 }}>
                <div className="vault-security-item">🛡 Transfers are checked by CYBERMIND AI before they leave your account</div>
              </div>
            </div>
          )}

          {page === "Security" && (
            <div className="vault-page" key="security">
              <div className="vault-bottom-grid">
                <div className="vault-panel">
                  <p className="vault-panel-title">🛡 Session security</p>
                  {[["Status", statusLabel, statusKey === "safe" ? "safe" : statusKey === "suspicious" ? "warn" : "danger"], ["Monitoring", "Active", "safe"],
                    ["Reference", `${sessionId.slice(0, 8).toUpperCase()}`, ""], ["Your IP", ip, ""], ["Signed in", `${Math.max(0, Math.floor((Date.now() - startedAt.current) / 60000))} min ago`, ""]].map(([k, v, cls]) => (
                    <div key={k} className="vault-metric-row"><span className="vault-metric-key">{k}</span><span className={`vault-metric-val${cls ? " " + cls : ""}`}>{cls ? "● " : ""}{v}</span></div>
                  ))}
                </div>
                <div className="vault-panel">
                  <p className="vault-panel-title">📊 What CYBERMIND sees</p>
                  {[["Typing speed", `${Math.round(metrics.cpm)} cpm`], ["Keystroke interval", `${Math.round(metrics.avg)} ms`], ["Rhythm variation", `${Math.round(metrics.std)} ms`],
                    ["Mouse movement", `${(metrics.entropy * 100).toFixed(0)}%`], ["Clicks / min", `${metrics.clickRate}`]].map(([k, v]) => (
                    <div key={k} className="vault-metric-row"><span className="vault-metric-key">{k}</span><span className="vault-metric-val">{v}</span></div>
                  ))}
                  <p className="vault-fine">Only typing rhythm and mouse patterns are measured. What you type is never read or sent.</p>
                </div>
              </div>
            </div>
          )}

          {page === "Profile" && (
            <div className="vault-page" key="profile">
              <div className="vault-form-card">
                {[["Name", profile.full_name], ["Username", `@${profile.username}`], ["Account", profile.account_no], ["Plan", "Demo account"]].map(([k, v]) => (
                  <div key={k} className="vault-metric-row"><span className="vault-metric-key">{k}</span><span className="vault-metric-val">{v}</span></div>
                ))}
                <p className="vault-fine">This is a demo bank. Accounts and balances are for demonstration only; no real money moves.</p>
              </div>
            </div>
          )}
        </main>
      </div>

      {stepOpen && status !== "LOCKDOWN" && (
        <div className="vault-modal-back" role="dialog" aria-modal="true" aria-label="Verify it is you">
          <form className="vault-modal" onSubmit={verifyStepUp}>
            <div className="vault-modal-ico">🔑</div>
            <h3>Verify it's you</h3>
            <p>Re-enter your password to continue with this action.</p>
            <input type="password" autoFocus value={stepPw} onChange={e => setStepPw(e.target.value)} placeholder="Password" autoComplete="current-password" required />
            {stepMsg && <div className="vault-error-msg">⚠ {stepMsg}</div>}
            <div className="vault-btn-row">
              <button type="button" className="vault-ghost" onClick={() => { setStepOpen(false); setStepPw(""); setStepMsg("") }}>Cancel</button>
              <button type="submit" className="vault-review-btn" disabled={busy}>{busy ? "Checking…" : "Verify"}</button>
            </div>
          </form>
        </div>
      )}

      <FreezeOverlay sessionId={sessionId} status={status} reason={lockdownReason} onLogout={signOut} />
    </div>
  )
}
