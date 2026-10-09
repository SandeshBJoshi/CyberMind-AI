// Public product page: what CYBERMIND AI is, how it works, and the two ways in.
const PILLARS = [
  ['Stops credential stuffing', 'Groups login attempts by client fingerprint, not IP, so an attacker rotating through thousands of addresses still shows up as one campaign. Decoy accounts give near-zero-false-alarm alerts.'],
  ['Catches hijacked sessions', 'Learns how each user types, clicks and signs in. A stolen session behaving differently, or from a new device or network, is challenged or frozen.'],
  ['Explains every decision', 'Each verdict is allow, step-up or block, with the reasons in plain English, ready for your SIEM through CSV or JSON export.'],
]
const STEPS = [
  ['01', 'Connect your app', 'Add two small hooks: one on your login endpoint, one on signed-in pages.'],
  ['02', 'CYBERMIND learns', 'It builds a behavioural baseline per user and per client, with no change for your customers.'],
  ['03', 'Threats are contained', 'Risky logins and sessions are stepped up or frozen in milliseconds. Your team reviews and releases them in the console.'],
]

export default function Landing({ onConsole, onVault }) {
  return (
    <div className="cm-site">
      <header className="cm-site-nav">
        <div className="cm-site-brand mono">CYBERMIND AI</div>
        <nav>
          <a href="#how" onClick={(e) => { e.preventDefault(); document.getElementById('how')?.scrollIntoView({ behavior: 'smooth' }) }}>How it works</a>
          <button className="cm-site-link" onClick={onVault}>Live demo →</button>
          <button className="cm-site-cta" onClick={onConsole}>Sign in to console</button>
        </nav>
      </header>

      <section className="cm-site-hero">
        <div className="cm-eyebrow mono"><span className="cm-dot" /> BEHAVIORAL THREAT PROTECTION</div>
        <h1>Stop account takeover <em>before it starts.</em></h1>
        <p>
          CYBERMIND AI sits behind your login and your signed-in sessions. It spots credential-stuffing campaigns and
          hijacked sessions from behaviour, not just IP addresses, and contains them automatically.
        </p>
        <div className="cm-site-actions">
          <button className="cm-site-cta big" onClick={onVault}>Try the live demo →</button>
          <button className="cm-site-ghost big" onClick={onConsole}>Open the console →</button>
        </div>
        <div className="cm-site-note mono">DEMO: a sample bank app (customer side) and the security console (defender side)</div>
      </section>

      <section className="cm-site-grid">
        {PILLARS.map(([t, d]) => (
          <article key={t} className="cm-site-card"><b>{t}</b><span>{d}</span></article>
        ))}
      </section>

      <section id="how" className="cm-site-how">
        <h2>How it works</h2>
        <div className="cm-site-steps">
          {STEPS.map(([n, t, d]) => (
            <div key={n} className="cm-site-step"><i className="mono">{n}</i><b>{t}</b><span>{d}</span></div>
          ))}
        </div>
      </section>

      <section className="cm-site-two">
        <button className="cm-entry" onClick={onVault}>
          <span className="cm-entry-k mono">FOR CUSTOMERS</span>
          <b>Customer demo app</b>
          <span>A sample bank protected by CYBERMIND. Sign in, then behave normally, or like a bot, and watch it react.</span>
          <em className="mono">OPEN THE DEMO →</em>
        </button>
        <button className="cm-entry" onClick={onConsole}>
          <span className="cm-entry-k mono">FOR SECURITY TEAMS</span>
          <b>Security console</b>
          <span>See every detection, contain sessions, run attack simulations and connect apps. Admin sign-in required.</span>
          <em className="mono">SIGN IN →</em>
        </button>
      </section>

      <footer className="cm-site-foot mono">© CYBERMIND AI · Behavioral threat protection</footer>
    </div>
  )
}
