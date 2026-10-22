// The Analyst Assistant's structured report: summary, attacks performed, suggested actions, CVEs and what defines them, agents involved.
const LEVEL = { CRITICAL: 'bad', HIGH: 'bad', MEDIUM: 'warn', LOW: 'ok', UNKNOWN: 'dim' }
const SEV = (s) => ({ CRITICAL: 'bad', HIGH: 'bad', MEDIUM: 'warn', LOW: 'ok' }[String(s || '').toUpperCase()] || 'dim')
const CAT_ORDER = ['MITIGATION', 'DETECTION', 'RESPONSE', 'HARDENING']
const CAT_HINT = { MITIGATION: 'Reduce the chance or impact', DETECTION: 'Spot it when it happens', RESPONSE: 'What to do when it happens', HARDENING: 'Make the system tougher' }
const STATUS = { ok: 'ok', partial: 'warn', failed: 'bad' }

function Tags({ label, items }) {
  if (!items || !items.length) return null
  return (
    <div className="rp-tags"><span className="mono rp-tag-label">{label}</span>
      {items.map(t => (
        <a key={t.id} href={t.url} target="_blank" rel="noreferrer noopener" className={`rp-tag ${t.source === 'report' ? 'cited' : 'guess'}`}
          title={t.source === 'report' ? 'This id appears in the report' : 'Suggested by the model, not found in the report. Verify it.'}>
          <b className="mono">{t.id}</b>{t.name ? ` ${t.name}` : ''}{t.source === 'report' ? '' : ' · model-suggested'}
        </a>
      ))}
    </div>
  )
}

function Section({ n, title, sub, children }) {
  return (
    <section className="rp-section">
      <header><span className="mono rp-n">{n}</span><div><h3>{title}</h3>{sub && <p>{sub}</p>}</div></header>
      {children}
    </section>
  )
}

export default function IntelReport({ result }) {
  const r = result.report
  const cves = result.cves || []
  const trace = result.trace || []
  return (
    <div className="rp">
      <div className="rp-top">
        <h2>{r.title || 'Threat intelligence briefing'}</h2>
        <div className="rp-meta">
          <span className={`rp-level ${LEVEL[r.threat_level]}`} title="The AI analyst's own rating; the report may not state one">THREAT LEVEL · {r.threat_level}</span>
          {r.affected_assets.map(a => <span key={a} className="rp-asset">{a}</span>)}
        </div>
      </div>

      <Section n="01" title="Summary of the report" sub="What your uploaded report says about the question">
        <p className="rp-summary">{r.summary || 'The retrieved material did not provide enough to summarise.'}</p>
        {r.gaps && <p className="rp-gaps"><b className="mono">NOT COVERED BY THE REPORT</b> {r.gaps}</p>}
      </Section>

      <Section n="02" title="Attacks performed" sub={`${r.attacks.length} attack${r.attacks.length === 1 ? '' : 's'} or technique${r.attacks.length === 1 ? '' : 's'} described`}>
        {r.attacks.length === 0 && <p className="cm-muted">No specific attack was described in the retrieved material.</p>}
        <div className="rp-attacks">
          {r.attacks.map((a, i) => (
            <article key={i} className="rp-attack">
              <h4><span className="mono">{String(i + 1).padStart(2, '0')}</span>{a.name}</h4>
              <p>{a.description}</p>
              {a.evidence && <blockquote>{a.evidence}</blockquote>}
              <Tags label="MITRE ATT&CK" items={a.attack_ids} />
              <Tags label="CWE (weakness)" items={a.cwe_ids} />
              <Tags label="CAPEC (attack pattern)" items={a.capec_ids} />
            </article>
          ))}
        </div>
      </Section>

      <Section n="03" title="Suggested actions and techniques" sub="Ordered by priority inside each group">
        {r.actions.length === 0 && <p className="cm-muted">No actions were suggested in the retrieved material.</p>}
        <div className="rp-actions">
          {CAT_ORDER.map(cat => {
            const rows = r.actions.filter(a => a.category === cat)
            if (!rows.length) return null
            const rank = { HIGH: 0, MEDIUM: 1, LOW: 2 }
            return (
              <div key={cat} className="rp-action-group">
                <h4 className="mono">{cat}<small>{CAT_HINT[cat]}</small></h4>
                <ul>{[...rows].sort((x, y) => rank[x.priority] - rank[y.priority]).map((a, i) => (
                  <li key={i}><span className={`rp-pri ${a.priority === 'HIGH' ? 'bad' : a.priority === 'MEDIUM' ? 'warn' : 'dim'}`}>{a.priority}</span><span>{a.action}{a.source === 'report' ? <em className="rp-src">from the report</em> : <em className="rp-src bp" title="Added by the AI from general knowledge; the report does not say this">best practice, not in the report</em>}</span></li>
                ))}</ul>
              </div>
            )
          })}
        </div>
      </Section>

      <Section n="04" title="CVEs and what defines them" sub="CVE ids found in your report, checked against the NIST National Vulnerability Database (NVD)">
        {cves.length === 0 && <p className="cm-muted">No CVE identifiers appear in the retrieved material, so nothing was looked up. (CVEs are never taken from the AI, only from your report.)</p>}
        {cves.length > 0 && (
          <div className="em-scroll">
            <table className="em-table rp-cves">
              <thead><tr><th>CVE</th><th>SEVERITY</th><th>WHAT IT IS</th><th>WEAKNESS DEFINITION (CWE)</th></tr></thead>
              <tbody>
                {cves.map(c => (
                  <tr key={c.id}>
                    <td><a href={c.url} target="_blank" rel="noreferrer noopener" className="mono rp-cve">{c.id}</a><small>{c.published && `published ${c.published}`}</small></td>
                    <td>{c.status === 'verified' ? <span className={`rp-sev ${SEV(c.severity)}`}>{c.cvss != null ? `${c.cvss} ` : ''}{c.severity || '—'}</span> : <span className="rp-sev dim">UNVERIFIED</span>}</td>
                    <td>{c.status === 'verified' ? c.description : c.status === 'not_found' ? 'Not found in the NVD, so its details could not be confirmed.' : (c.note || 'The NVD could not be reached.')}</td>
                    <td>{c.cwes && c.cwes.length ? c.cwes.map(w => <a key={w.id} href={w.url} target="_blank" rel="noreferrer noopener" className="rp-tag cited"><b className="mono">{w.id}</b>{w.name ? ` ${w.name}` : ''}</a>) : <span className="cm-muted">{c.status === 'verified' ? 'not classified' : '—'}</span>}</td>
                  </tr>))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section n="05" title="Agents involved" sub={`${trace.length} steps, in the order they ran`}>
        <ol className="rp-agents">
          {trace.map((t, i) => (
            <li key={i}>
              <span className={`rp-dot ${STATUS[t.status] || 'ok'}`} title={t.status} />
              <div><b>{t.agent}</b><em>{t.role}</em><p>{t.detail}</p></div>
              <span className="mono rp-ms">{t.ms >= 1000 ? `${(t.ms / 1000).toFixed(1)} s` : `${t.ms} ms`}</span>
            </li>
          ))}
        </ol>
      </Section>
    </div>
  )
}
