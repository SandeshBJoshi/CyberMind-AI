import { useEffect, useRef, useState } from 'react'
import {
  analyzeEmailFile, analyzeEmailText, getEmailHistory, getEmailAnalysis,
  deleteEmailAnalysis, downloadEmailReport, getEmailAiStatus,
} from '../api'

const TIER = { PHISHING: { cls: 'bad', label: 'PHISHING', text: 'Very likely a malicious message' },
  SUSPICIOUS: { cls: 'warn', label: 'SUSPICIOUS', text: 'Could not be verified as safe' },
  SAFE: { cls: 'ok', label: 'NO STRONG SIGNS', text: 'No strong phishing signs found' } }
const SUMMARY = {
  PHISHING: 'Several independent checks agree this message is built to trick the recipient. Treat it as an attack.',
  SUSPICIOUS: 'Some checks raised concerns but the evidence is not conclusive. Verify it before acting on it.',
  SAFE: 'The checks found no strong signs of phishing. This is not a guarantee: targeted attacks can look clean.',
}
const ago = (t) => { const s = Math.max(1, Math.round((Date.now() - new Date(t + (String(t).endsWith('Z') ? '' : 'Z')).getTime()) / 1000)); return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago` }

const AGREE = { agree: ['ok', 'AGREES with the rules'], partly: ['warn', 'PARTLY AGREES with the rules'], disagree: ['bad', 'DISAGREES with the rules'] }

function AiPanel({ ai }) {
  if (!ai) return null
  if (!ai.available) {
    return (
      <section className="em-ai off"><span className="mono em-k">AI ANALYST</span><p className="cm-muted">{ai.error}</p></section>
    )
  }
  const t = TIER[ai.verdict], a = AGREE[ai.agreement]
  return (
    <section className="em-ai">
      <header>
        <div><span className="mono em-k">AI ANALYST · {ai.model} on Groq · {(ai.latency_ms / 1000).toFixed(1)}s</span>
          <h3>Opinion: <span className={`em-pill ${t.cls}`}>{ai.verdict}</span> <small>{ai.confidence}% confident</small></h3></div>
        <span className={`em-pill ${a[0]}`}>{a[1]}</span>
      </header>
      <p>{ai.summary}</p>
      {ai.reasons.length > 0 && <ul>{ai.reasons.map((x, i) => <li key={i}>{x}</li>)}</ul>}
      {ai.extra_signals.length > 0 && <p className="em-extra"><b className="mono">NOTICED THAT THE RULES DID NOT REPORT:</b> {ai.extra_signals.join(' · ')}</p>}
      <p className="cm-muted em-fine">The AI opinion is advisory. The verdict above comes from the rule-based checks, which an email cannot talk its way around.</p>
    </section>
  )
}

function CopyList({ title, items }) {
  const [done, setDone] = useState(false)
  if (!items || !items.length) return null
  return (
    <div className="em-ind">
      <div className="em-ind-head"><b className="mono">{title}</b>
        <button className="pro-btn sm" onClick={() => { navigator.clipboard?.writeText(items.join('\n')); setDone(true); setTimeout(() => setDone(false), 1200) }}>{done ? 'COPIED' : 'COPY'}</button>
      </div>
      <ul>{items.map(i => <li key={i} className="mono">{i}</li>)}</ul>
    </div>
  )
}

function Result({ rec, onDelete, onError }) {
  const r = rec.result, e = r.email, t = TIER[r.verdict]
  return (
    <section className={`pro-panel em-result ${t.cls}`}>
      <header className="em-banner">
        <div><span className="mono em-k">VERDICT</span><h2>{t.label}</h2><p>{t.text}. {SUMMARY[r.verdict]}</p></div>
        <div className="em-score"><b>{r.score}</b><span className="mono">RISK SCORE</span><small>suspicious ≥ {r.thresholds.suspicious} · phishing ≥ {r.thresholds.phishing}</small></div>
      </header>

      <AiPanel ai={r.ai} />

      <div className="em-actions-row">
        <button className="pro-btn" onClick={() => downloadEmailReport(rec.id, 'pdf').catch(x => onError(x.message))}>⬇ DOWNLOAD PDF REPORT</button>
        <button className="pro-btn" onClick={() => downloadEmailReport(rec.id, 'md').catch(x => onError(x.message))}>⬇ MARKDOWN</button>
        <button className="pro-btn danger sm" onClick={() => onDelete(rec.id)}>DELETE</button>
      </div>

      <div className="em-grid">
        <div>
          <h3 className="mono">THE MESSAGE</h3>
          <dl className="em-dl">
            <dt>From</dt><dd>{e.from_name} &lt;{e.from_addr}&gt;</dd>
            <dt>Reply-To</dt><dd>{e.reply_to || '(none)'}</dd>
            <dt>Subject</dt><dd>{e.subject}</dd>
            <dt>Date</dt><dd>{e.date || '—'}</dd>
            <dt>SHA-256</dt><dd className="mono em-hash">{e.raw_sha256}</dd>
          </dl>
        </div>
        <div>
          <h3 className="mono">WHY THIS VERDICT</h3>
          {r.reasons.length === 0 && <p className="cm-muted">No warning signs found.</p>}
          <ul className="em-reasons">
            {r.reasons.map(x => (
              <li key={x.code}><b className="mono">+{x.points}</b><div><span>{x.text}</span>{x.evidence && <em>{x.evidence}</em>}</div></li>
            ))}
          </ul>
          {r.positives.map(p => <p key={p} className="em-good">✓ {p}</p>)}
        </div>
      </div>

      {e.links.length > 0 && (
        <>
          <h3 className="mono">LINKS ({e.links.length})</h3>
          <div className="em-scroll"><table className="em-table"><thead><tr><th>SHOWN AS</th><th>REALLY GOES TO</th></tr></thead>
            <tbody>{e.links.slice(0, 12).map((l, i) => <tr key={i}><td>{l.text || <i>(plain text link)</i>}</td><td className="mono">{l.href}</td></tr>)}</tbody></table></div>
        </>
      )}
      {e.attachments.length > 0 && (
        <>
          <h3 className="mono">ATTACHMENTS ({e.attachments.length}) <small>named and hashed only, never opened</small></h3>
          <div className="em-scroll"><table className="em-table"><thead><tr><th>FILE</th><th>TYPE</th><th>SHA-256</th></tr></thead>
            <tbody>{e.attachments.map((a, i) => <tr key={i}><td>{a.filename}</td><td>{a.content_type}</td><td className="mono">{a.sha256}</td></tr>)}</tbody></table></div>
        </>
      )}

      <div className="em-grid">
        <div>
          <h3 className="mono">INDICATORS TO BLOCK</h3>
          <CopyList title="DOMAINS" items={r.indicators.domains} />
          <CopyList title="IP ADDRESSES" items={r.indicators.ips} />
          <CopyList title="SENDER ADDRESSES" items={r.indicators.emails} />
          <CopyList title="FILE HASHES (SHA-256)" items={r.indicators.file_hashes.map(h => h.sha256)} />
        </div>
        <div>
          <h3 className="mono">MITRE ATT&amp;CK</h3>
          <div className="em-chips">{r.attack.length ? r.attack.map(a => <span key={a.id} className="em-chip"><b className="mono">{a.id}</b> {a.name}</span>) : <span className="cm-muted">None identified.</span>}</div>
          <h3 className="mono">WHAT TO DO</h3>
          <ol className="em-todo">{r.actions.map(a => <li key={a}>{a}</li>)}</ol>
        </div>
      </div>
    </section>
  )
}

export default function EmailAnalysis({ onAnalyzed }) {
  const [mode, setMode] = useState('upload')             // upload | paste
  const [history, setHistory] = useState([])
  const [current, setCurrent] = useState(null)
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const fileRef = useRef(null)
  const [aiStatus, setAiStatus] = useState(null)
  const [useAi, setUseAi] = useState(false)
  const [model, setModel] = useState('')

  const loadAiStatus = () => getEmailAiStatus()
    .then(s => { setAiStatus(s); setUseAi(!!s.available); setModel(s.model) })
    .catch(() => setAiStatus({ available: false, failed: true }))
  const loadHistory = () => getEmailHistory().then(setHistory).catch(() => {})
  useEffect(() => {
    loadHistory()
    loadAiStatus()
  }, [])
  const opts = { ai: useAi, model }

  async function run(fn) {
    setBusy(true); setError('')
    try {
      const rec = await fn()
      setCurrent(rec); loadHistory(); onAnalyzed && onAnalyzed(rec)
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  const open = (id) => getEmailAnalysis(id).then(setCurrent).catch(err => setError(err.message))
  const remove = async (id) => {
    try { await deleteEmailAnalysis(id); setCurrent(null); loadHistory() } catch (err) { setError(err.message) }
  }

  return (
    <div className="em">
      <section className="pro-panel">
        <div className="em-intro">
          <h3 className="mono" style={{ margin: 0 }}>ANALYSE AN EMAIL</h3>
          <p className="cm-muted">Reads the headers, links and attachments of an email and explains why it is or is not phishing. The message is only read: links are never opened and attachments are never run. Only the result is stored, not the email.</p>
        </div>
        <div className="em-aibar">
          <label className={`em-switch ${aiStatus && aiStatus.available ? '' : 'off'}`}>
            <input type="checkbox" checked={useAi} disabled={!aiStatus || !aiStatus.available} onChange={e => setUseAi(e.target.checked)} />
            <span>AI analyst (Groq)</span>
          </label>
          {aiStatus && aiStatus.available && (
            <select value={model} onChange={e => setModel(e.target.value)} disabled={!useAi} aria-label="AI model">
              {aiStatus.models.map(m => <option key={m} value={m}>{m.replace('openai/', '')}{m.endsWith('-20b') ? ' · faster' : ' · stronger'}</option>)}
            </select>
          )}
          <span className="cm-muted em-fine">
            {!aiStatus ? 'Checking the AI analyst…'
              : aiStatus.failed ? <>Could not check the AI analyst (is the backend running the latest code?). <button className="pro-btn sm" onClick={loadAiStatus}>RETRY</button></>
              : aiStatus.available ? (useAi ? 'Sends the email text and the scanner findings to Groq for a second opinion. Attachments are never sent.' : 'Off: only the rule-based checks run, nothing leaves this server.')
              : 'Not configured: add GROQ_API_KEY to backend/.env and restart the backend to enable it.'}
          </span>
        </div>
        <div className="cm-seg em-seg" role="tablist">
          {[['upload', 'UPLOAD .EML'], ['paste', 'PASTE SOURCE']].map(([k, l]) => (
            <button key={k} role="tab" className={mode === k ? 'on' : ''} onClick={() => setMode(k)}>{l}</button>
          ))}
        </div>

        {mode === 'upload' && (
          <div className="em-upload">
            <input ref={fileRef} type="file" accept=".eml,.txt,message/rfc822" />
            <button className="pro-btn" disabled={busy} onClick={() => { const f = fileRef.current?.files?.[0]; if (!f) { setError('Choose an .eml file first.'); return } run(() => analyzeEmailFile(f, opts)) }}>{busy ? 'ANALYSING…' : 'ANALYSE FILE'}</button>
            <p className="cm-muted">In Gmail: open the email → ⋮ → "Download message". In Outlook: save the message as .eml.</p>
          </div>
        )}
        {mode === 'paste' && (
          <div className="em-paste">
            <textarea value={text} onChange={e => setText(e.target.value)} placeholder={'Paste the full message source here (headers and body).\nGmail: ⋮ → "Show original".  Outlook: File → Properties → Internet headers.'} rows={9} />
            <button className="pro-btn" disabled={busy || text.trim().length < 10} onClick={() => run(() => analyzeEmailText(text, opts))}>{busy ? 'ANALYSING…' : 'ANALYSE TEXT'}</button>
          </div>
        )}
        {error && <div className="cm-error" role="alert">⚠ {error}</div>}
      </section>

      {current && <Result rec={current} onDelete={remove} onError={setError} />}

      <section className="pro-panel">
        <h3 className="mono" style={{ marginTop: 0 }}>RECENT ANALYSES</h3>
        {history.length === 0 ? <p className="cm-muted">Nothing analysed yet. Upload an .eml file or paste an email's source above.</p> : (
          <div className="em-scroll"><table className="em-table em-history"><thead><tr><th>WHEN</th><th>VERDICT</th><th>SCORE</th><th>FROM</th><th>SUBJECT</th></tr></thead>
            <tbody>{history.map(h => (
              <tr key={h.id} onClick={() => open(h.id)} className={current && current.id === h.id ? 'on' : ''}>
                <td>{ago(h.created_at)}</td><td><span className={`em-pill ${TIER[h.verdict].cls}`}>{h.verdict}</span></td><td className="mono">{h.score}</td><td>{h.sender}</td><td>{h.subject}</td>
              </tr>))}</tbody></table></div>
        )}
      </section>
    </div>
  )
}
