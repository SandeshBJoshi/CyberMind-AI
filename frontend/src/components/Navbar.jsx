import { Fragment } from 'react'
// Sidebar navigation (file name kept so existing imports keep working)
const ICONS = {
  dashboard: <><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></>,
  attacker: <><path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z" /></>,
  logs: <><path d="M5 4h14v16H5z" /><path d="M8 9h8M8 13h8M8 17h5" /></>,
  email: <><rect x="3" y="5" width="18" height="14" rx="2.5" /><path d="m3.5 7 8.5 6 8.5-6" /></>,
  sessions: <><circle cx="9" cy="8" r="3.2" /><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6" /><circle cx="17" cy="9" r="2.4" /><path d="M16 14.2c2.9 0 5 2 5 4.8" /></>,
  integrate: <><path d="M9 7 4 12l5 5M15 7l5 5-5 5" /></>,
  portal: <><rect x="3" y="4" width="18" height="16" rx="2.5" /><path d="M3 9h18" /><circle cx="6.5" cy="6.5" r=".6" /></>,
  cybermind: <><path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3Z" /><path d="M18.5 16l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2Z" /></>,
}

// Ordered like an operator's day: watch → investigate → contain → test the defence → ask for help.
const TABS = [
  { id: 'dashboard', label: 'Overview', key: '1', group: 'MONITOR' },
  { id: 'logs', label: 'Detections', key: '2', group: 'MONITOR' },
  { id: 'email', label: 'Email Analysis', key: '3', group: 'MONITOR' },
  { id: 'sessions', label: 'Active Sessions', key: '4', group: 'RESPOND' },
  { id: 'attacker', label: 'Attack Simulator', key: '5', group: 'VALIDATE' },
  { id: 'integrate', label: 'Integrations', key: '6', group: 'SETUP' },
  { id: 'cybermind', label: 'Analyst Assistant', key: '7', group: 'ASSIST' },
]
export const openVaultApp = () => window.open(`${window.location.pathname}#user-portal`, '_blank', 'noopener')
export { TABS }

const STATUS_LABEL = { SAFE: 'SYSTEM SECURE', SUSPICIOUS: 'ELEVATED WATCH', LOCKDOWN: 'LOCKDOWN ACTIVE' }

export default function Navbar({ view, setView, onLogout, threat = 'SAFE', onOpenPalette }) {
  return (
    <aside className="cm-rail">
      <div className="cm-brand">
        <svg width="30" height="30" viewBox="0 0 32 32" fill="none" aria-hidden="true">
          <path d="M16 2 4 9v14l12 7 12-7V9L16 2Z" stroke="currentColor" strokeWidth="1.6" />
          <circle cx="16" cy="16" r="4" fill="currentColor" />
          <path d="M16 12V2M16 20v10M12.5 14 4 9M19.5 18 28 23M12.5 18 4 23M19.5 14 28 9" stroke="currentColor" strokeWidth="1" opacity=".55" />
        </svg>
        <div>
          <div className="cm-brand-name">CYBERMIND AI</div>
          <div className="cm-brand-sub mono">SECURITY CONSOLE</div>
        </div>
      </div>

      <div className="cm-rail-status" data-threat={threat}>
        <span className="cm-dot" />
        <div>
          <div className="mono cm-rail-status-k">STATUS</div>
          <div className="cm-rail-status-v">{STATUS_LABEL[threat] || 'Secure'}</div>
        </div>
      </div>

      <nav className="cm-nav">
        {TABS.map((t, i) => (
          <Fragment key={t.id}>
          {(i === 0 || TABS[i - 1].group !== t.group) && <div className="cm-nav-group mono">{t.group}</div>}
          <button className={`cm-nav-btn ${view === t.id ? 'active' : ''}`} onClick={() => setView(t.id)}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{ICONS[t.id]}</svg>
            <span>{t.label}</span>
            <kbd className="mono">{t.key}</kbd>
          </button>
          </Fragment>
        ))}
      </nav>

      <div className="cm-rail-foot">
        <button className="cm-vault-btn" onClick={openVaultApp}>
          <span>Open customer demo app</span><span aria-hidden="true">↗</span>
        </button>
        <button className="cm-palette-btn" onClick={onOpenPalette}>
          <span>Quick actions</span><kbd className="mono">Ctrl K</kbd>
        </button>
        <button className="cm-logout" onClick={onLogout}>Log out</button>
      </div>
    </aside>
  )
}
