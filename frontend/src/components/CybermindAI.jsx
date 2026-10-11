import { useEffect, useRef, useState, useMemo } from 'react'
import { marked } from 'marked'
import IntelReport from './IntelReport'
import { clearCybermindStore, getCybermindStatus, ingestCybermindReport, queryCybermind } from '../api'

// Configure marked options
marked.setOptions({
  gfm: true,
  breaks: true,
})

function extractThreatHUD(text) {
  if (!text) return null
  const threatLevelMatch = text.match(/THREAT LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)/i)
  const impactMatch = text.match(/IMPACT:\s*([^\n\r]+)/i)
  const assetMatch = text.match(/AFFECTED ASSET:\s*([^\n\r]+)/i)
  const attackTypeMatch = text.match(/ATTACK TYPE:\s*([^\n\r]+)/i)

  if (!threatLevelMatch && !impactMatch && !assetMatch && !attackTypeMatch) {
    return null
  }
  return {
    level: threatLevelMatch ? threatLevelMatch[1].toUpperCase() : null,
    impact: impactMatch ? impactMatch[1].trim() : null,
    asset: assetMatch ? assetMatch[1].trim() : null,
    attackType: attackTypeMatch ? attackTypeMatch[1].trim() : null,
  }
}

function renderSOCMarkdown(content) {
  if (!content) return ''
  let enriched = content
  // Format Threat Level text
  enriched = enriched.replace(
    /THREAT LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)/gi,
    (m, p1) => `<span class="soc-level-pill ${p1.toLowerCase()}">THREAT LEVEL: ${p1.toUpperCase()}</span>`
  )
  // Format MITRE ATT&CK technique IDs
  enriched = enriched.replace(
    /\b(T\d{4}(?:\.\d{3})?)\b/g,
    '<span class="soc-tag-mono">$1</span>'
  )
  // Format CVE identifiers
  enriched = enriched.replace(
    /\b(CVE-\d{4}-\d{4,7})\b/gi,
    '<span class="soc-tag-mono">$1</span>'
  )
  return marked.parse(enriched)
}

export default function CybermindAI() {
  const [status, setStatus] = useState(null)
  const [file, setFile] = useState(null)
  const [query, setQuery] = useState('')
  const [model, setModel] = useState('openai/gpt-oss-20b')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [copied, setCopied] = useState(false)
  const fileRef = useRef(null)

  async function refresh() {
    try {
      const data = await getCybermindStatus()
      setStatus(data)
      setModel(current => current || data.default_model)
    } catch (error) {
      setMessage(error.message)
    }
  }

  useEffect(() => { refresh() }, [])

  async function upload() {
    if (!file) return
    setBusy(true); setMessage('INDEXING CYBERSECURITY REPORT…')
    try {
      const data = await ingestCybermindReport(file)
      setMessage(`${data.message} — ${data.chunks} intelligence chunks ready.`)
      setFile(null)
      if (fileRef.current) fileRef.current.value = ''
      await refresh()
    } catch (error) { setMessage(error.message) } finally { setBusy(false) }
  }

  async function analyze() {
    if (!query.trim()) return
    setBusy(true); setMessage('CYBERMIND INTEL IS BUILDING A GROUNDED ADVISORY…'); setResult(null)
    try {
      setResult(await queryCybermind({ query, model_choice: model }))
      setMessage('ANALYSIS COMPLETE')
    } catch (error) { setMessage(error.message) } finally { setBusy(false) }
  }

  async function clearStore() {
    if (!window.confirm('Clear only the Analyst Assistant vector store? Threat-detection logs and sessions are unaffected.')) return
    setBusy(true)
    try { setMessage((await clearCybermindStore()).message); setResult(null); await refresh() }
    catch (error) { setMessage(error.message) } finally { setBusy(false) }
  }

  function handleCopy() {
    if (!result?.response) return
    navigator.clipboard.writeText(result.response)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function handleExport() {
    if (!result?.response) return
    const blob = new Blob([result.response], { type: 'text/markdown;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', `CyberMind_Intel_Advisory_${Date.now()}.md`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  const audit = result?.validation_result || {}
  const hud = useMemo(() => extractThreatHUD(result?.response), [result?.response])
  const htmlContent = useMemo(() => renderSOCMarkdown(result?.response), [result?.response])
  const score = audit.groundedness_score ?? 5

  return (
    <div className="cybermind-page">
      <div className="glass panel cybermind-hero glowing-border">
        <div>
          <div className="panel-title"><span className="bar" /> CYBERMIND INTEL // INTELLIGENCE WORKBENCH</div>
          <h1>Report-grounded threat intelligence.</h1>
          <p>Ingest security reports, retrieve them through the isolated Analyst Assistant knowledge store, and generate a validated cyber advisory without touching detection, lockdown, or security-log data.</p>
        </div>
        <div className="cybermind-stat"><span>INDEXED VECTORS</span><strong>{status?.count ?? '—'}</strong></div>
      </div>

      <div className="grid grid-2" style={{ marginTop: 20 }}>
        <section className="glass panel">
          <div className="panel-title"><span className="bar" /> INTEL UPLINK</div>
          <p className="cybermind-copy">Upload a PDF incident report, assessment, playbook, or threat bulletin. Files are indexed only in Analyst Assistant’s separate vector store.</p>
          <input ref={fileRef} className="cybermind-file" type="file" accept="application/pdf,.pdf" onChange={event => setFile(event.target.files?.[0] || null)} />
          {file && <div className="cybermind-file-name">PDF READY // {file.name}</div>}
          <button className="btn btn-block" disabled={!file || busy} onClick={upload}>{busy ? 'PROCESSING…' : '↑ INDEX PDF REPORT'}</button>
          <div className="cybermind-docs">
            <div className="field-label">KNOWLEDGE REPOSITORY // {status?.documents?.length || 0} FILES</div>
            {status?.documents?.length ? status.documents.map(name => <div className="tag" key={name}>PDF {name}</div>) : <div className="feed-empty">No reports indexed yet.</div>}
          </div>
          <button className="btn btn-outline cybermind-clear" disabled={busy || !status?.count} onClick={clearStore}>CLEAR CYBERMIND INTEL STORE</button>
        </section>

        <section className="glass panel">
          <div className="panel-title"><span className="bar" /> THREAT ANALYSIS TERMINAL</div>
          <label className="field-label">QUERY // CVE, INCIDENT, THREAT ACTOR, OR POLICY QUESTION</label>
          <textarea className="cybermind-query" value={query} onChange={event => setQuery(event.target.value)} placeholder="Explain the impact and mitigation priority for the vulnerabilities in the uploaded report." />
          <label className="field-label">INTELLIGENCE MODEL</label>
          <select className="attacker-select cybermind-select" value={model} onChange={event => setModel(event.target.value)}>
            <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
            <option value="gemini-1.5-pro">Gemini 1.5 Pro</option>
            <option value="openai/gpt-oss-20b">GPT OSS 20B (Groq)</option>
            <option value="openai/gpt-oss-120b">GPT OSS 120B (Groq)</option>
          </select>
          <button className="btn btn-warning btn-block" disabled={!query.trim() || busy} onClick={analyze}>{busy ? 'ANALYZING…' : '✦ EXECUTE CYBERMIND INTEL ANALYSIS'}</button>
          {message && <div className={`cybermind-message ${message.includes('failed') || message.includes('not configured') ? 'error' : ''}`}>{message}</div>}
        </section>
      </div>

      {result && <section className="glass panel cybermind-results">
        <div className="soc-header-bar">
          <div className="soc-classification">
            <span className="soc-classification-dot" />
            <span>CYBER THREAT INTELLIGENCE BRIEFING // SOC ADVISORY</span>
          </div>
          <div className="soc-header-actions">
            <button className="soc-action-btn" onClick={handleCopy}>
              {copied ? '✓ COPIED' : '📋 COPY INTEL'}
            </button>
            <button className="soc-action-btn" onClick={handleExport}>
              ⬇ EXPORT .MD
            </button>
          </div>
        </div>

        <div className="cybermind-trace">
          EXECUTION PIPELINE // {result.steps?.join('  →  ') || 'complete'}
        </div>

        {result.report ? <IntelReport result={result} /> : (<>
        {hud && (
          <div className="soc-threat-hud">
            {hud.level && (
              <div className="soc-hud-card">
                <div className="soc-hud-label">THREAT LEVEL</div>
                <div className="soc-hud-val">
                  <span className={`soc-level-pill ${hud.level.toLowerCase()}`}>{hud.level}</span>
                </div>
              </div>
            )}
            {hud.attackType && (
              <div className="soc-hud-card">
                <div className="soc-hud-label">CLASSIFIED ATTACK TYPE</div>
                <div className="soc-hud-val">{hud.attackType}</div>
              </div>
            )}
            {hud.asset && (
              <div className="soc-hud-card">
                <div className="soc-hud-label">TARGET ASSET</div>
                <div className="soc-hud-val">{hud.asset}</div>
              </div>
            )}
            {hud.impact && (
              <div className="soc-hud-card">
                <div className="soc-hud-label">OBSERVED IMPACT</div>
                <div className="soc-hud-val">{hud.impact}</div>
              </div>
            )}
          </div>
        )}

        {result.plan && (
          <details className="cybermind-details">
            <summary>AGENT PLAN & EXECUTION TRACE</summary>
            <pre>{result.plan}</pre>
          </details>
        )}

        <article
          className="cybermind-report-content"
          dangerouslySetInnerHTML={{ __html: htmlContent }}
        />
        </>)}

        <div className="soc-audit-card">
          <div className="soc-audit-top">
            <div className="soc-meter-wrap">
              <span className="soc-meter-label">GROUNDEDNESS {score}/5</span>
              <div className="soc-meter-pips">
                {[1, 2, 3, 4, 5].map(pip => (
                  <div
                    key={pip}
                    className={`soc-pip ${pip <= score ? (score >= 4 ? 'active' : 'active-amber') : ''}`}
                  />
                ))}
              </div>
            </div>

            <div className={`soc-audit-status ${audit.hallucination_detected ? 'flagged' : 'valid'}`}>
              <span>{audit.hallucination_detected ? '⚠ HALLUCINATION FLAGGED' : '✓ STRICTLY GROUNDED IN SOURCE'}</span>
            </div>
          </div>

          {audit.reasoning && (
            <div className="soc-audit-reasoning">
              {audit.reasoning}
            </div>
          )}

          {!!result.sources?.length && (
            <div className="soc-sources-row">
              <span className="soc-sources-label">VERIFIED SOURCE DOCUMENTS:</span>
              {result.sources.map(src => (
                <span key={src} className="soc-source-pill">
                  📄 {src}
                </span>
              ))}
            </div>
          )}
        </div>
      </section>}
    </div>
  )
}
