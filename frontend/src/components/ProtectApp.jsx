import { useEffect, useState } from 'react'
import { API_BASE, getSecurityStatus, getDecoys } from '../api'

const LOGIN_SNIPPET = `// Server side: after every login attempt on YOUR app, tell CYBERMIND (key stays on your server)
await fetch("${API_BASE}/api/auth-events/login-attempt", {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-App-Key": process.env.CYBERMIND_APP_KEY },
  body: JSON.stringify({
    username, ip_address: clientIp, success: loginSucceeded,
    user_agent: req.headers["user-agent"], header_order: Object.keys(req.headers),
    password_sha1: sha1(password).toUpperCase(),   // never send the password itself
  }),
})  // reply: { decision: "allow" | "step_up" | "deny", reasons: [...] }  -> enforce it`

const SESSION_SNIPPET = `// 1. Your backend starts a protected session when a user signs in
//    POST ${API_BASE}/api/sessions/start   (admin token)  ->  { session_id, session_token }
// 2. The browser sends behaviour signals every ~2s using that session token
await fetch("${API_BASE}/api/events/behavior", {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-Session-Token": sessionToken },
  body: JSON.stringify({ session_id, event_type: "behavior", typing_speed_cpm, keystroke_avg_interval_ms,
                          mouse_click_rate, mouse_move_entropy, session_duration_sec }),
})  // reply: status SAFE | SUSPICIOUS | LOCKDOWN  (423 = frozen)
// 3. Before a sensitive action (transfer, password change) call POST /api/protected-action`

export default function ProtectApp() {
  const [status, setStatus] = useState(null)
  const [decoys, setDecoys] = useState([])
  useEffect(() => {
    getSecurityStatus().then(setStatus).catch(() => {})
    getDecoys().then(d => setDecoys(Array.isArray(d) ? d : d.decoys || [])).catch(() => {})
  }, [])

  return (
    <div className="lab">
      <div className="pro-panel">
        <h3 className="mono" style={{ marginTop: 0 }}>HOW A COMPANY PLUGS CYBERMIND INTO ITS APP</h3>
        <p style={{ color: 'var(--text-dim)', lineHeight: 1.6 }}>
          Your customers never see CYBERMIND. Your app reports two things to it: <b>login attempts</b> (from your server, to catch
          credential-stuffing campaigns) and <b>behaviour signals</b> (from the browser, to catch hijacked sessions). CYBERMIND answers
          with a decision your app enforces. The VaultApp demo is built exactly this way.
        </p>
        <ol className="posture" style={{ listStyle: 'decimal inside' }}>
          <li>Set an app key: put a long random value in <code>APP_API_KEYS</code> in the backend <code>.env</code>.</li>
          <li>Add the login hook below to your server's sign-in code.</li>
          <li>Add the session hook to your signed-in pages.</li>
          <li>Create decoy accounts below; no real person uses them, so any attempt on one is an attacker.</li>
        </ol>
      </div>

      <div className="pro-panel">
        <h3 className="mono" style={{ marginTop: 0 }}>1 · LOGIN PROTECTION HOOK</h3>
        <pre className="cm-code">{LOGIN_SNIPPET}</pre>
      </div>
      <div className="pro-panel">
        <h3 className="mono" style={{ marginTop: 0 }}>2 · SESSION PROTECTION HOOK</h3>
        <pre className="cm-code">{SESSION_SNIPPET}</pre>
      </div>

      <div className="pro-panel">
        <h3 className="mono" style={{ marginTop: 0 }}>THIS INSTANCE</h3>
        <ul className="posture">
          <li className="ok"><span>●</span> API base: <code>{API_BASE}</code></li>
          <li className={status ? 'ok' : 'bad'}><span>●</span> {status ? `Mode: ${status.mode || status.app_env || 'unknown'}` : 'Loading status…'}</li>
          <li className="ok"><span>●</span> {decoys.length} decoy account(s) active (manage them under Detections → Campaigns &amp; Decoys)</li>
        </ul>
      </div>
    </div>
  )
}
