import { useState } from 'react'
import { login } from '../api'

const POINTS = [
  ['Behavioral biometrics', 'Keystroke rhythm, device and IP churn read in real time.'],
  ['Hybrid detection', 'Six deterministic rules fused with an Isolation Forest ML engine.'],
  ['Automatic lockdown', 'Sessions freeze in milliseconds — only an admin can unlock them.'],
]

export default function Login({ onSuccess, onBack }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username.trim(), password)
      onSuccess()
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="cm-login">
      <section className="cm-login-copy">
        <div className="cm-eyebrow mono"><span className="cm-dot" /> SECURITY CONSOLE // SIGN IN</div>
        <h1>The mind that <em>never blinks.</em></h1>
        <p>Real-time behavioral threat detection and automated lockdown, watching every session so you don’t have to.</p>
        <ul>
          {POINTS.map(([t, d]) => (
            <li key={t}><b>{t}</b><span>{d}</span></li>
          ))}
        </ul>
      </section>

      <form className="cm-login-card" onSubmit={handleSubmit}>
        <div className="cm-login-brand">
          <svg width="34" height="34" viewBox="0 0 32 32" fill="none" aria-hidden="true">
            <path d="M16 2 4 9v14l12 7 12-7V9L16 2Z" stroke="currentColor" strokeWidth="1.6" />
            <circle cx="16" cy="16" r="4" fill="currentColor" />
            <path d="M16 12V2M16 20v10M12.5 14 4 9M19.5 18 28 23M12.5 18 4 23M19.5 14 28 9" stroke="currentColor" strokeWidth="1" opacity=".55" />
          </svg>
          <div><div className="cm-brand-name">CYBERMIND AI</div><div className="cm-brand-sub mono">SECURITY CONSOLE // SIGN IN</div></div>
        </div>

        <label className="cm-field-group">
          <span className="mono">USERNAME</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus />
        </label>
        <label className="cm-field-group">
          <span className="mono">PASSWORD</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" placeholder="••••••••••" />
        </label>
        {error && <div className="cm-error">⚠ {error}</div>}
        <button className="cm-submit" type="submit" disabled={loading}>
          <span>{loading ? 'AUTHENTICATING…' : 'AUTHENTICATE'}</span>
        </button>
        {onBack && <button type="button" className="cm-back-link mono" onClick={onBack}>← Back to CYBERMIND home</button>}
        <div className="cm-hint mono">Demo credentials come from your backend .env (ADMIN_USERNAME / ADMIN_PASSWORD).</div>
      </form>
    </div>
  )
}
