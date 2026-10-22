// Turn a raw User-Agent string into something an analyst can scan: "Chrome 154 · Windows"
export function shortDevice(ua = '') {
  if (!ua) return '—'
  const s = String(ua)
  const grab = (re) => { const m = s.match(re); return m ? m[1] : null }

  let browser = ''
  if (/TorBrowser|Tor-Exit/i.test(s)) browser = 'Tor'
  else if (/python-requests|python-urllib/i.test(s)) browser = 'Python client'
  else if (/curl\//i.test(s)) browser = 'curl'
  else if (grab(/Edg\/(\d+)/)) browser = `Edge ${grab(/Edg\/(\d+)/)}`
  else if (grab(/Firefox\/(\d+)/)) browser = `Firefox ${grab(/Firefox\/(\d+)/)}`
  else if (grab(/Chrome\/(\d+)/)) browser = `Chrome ${grab(/Chrome\/(\d+)/)}`
  else if (grab(/Version\/(\d+)[^)]*Safari/)) browser = `Safari ${grab(/Version\/(\d+)/)}`

  let os = ''
  if (/Windows/i.test(s)) os = 'Windows'
  else if (/Android/i.test(s)) os = 'Android'
  else if (/iPhone|iPad|iOS/i.test(s)) os = 'iOS'
  else if (/Mac OS X|Macintosh/i.test(s)) os = 'macOS'
  else if (/Linux/i.test(s)) os = 'Linux'

  const out = [browser, os].filter(Boolean).join(' · ')
  return out || (s.length > 30 ? `${s.slice(0, 30)}…` : s)
}

export function relTime(ts, now = Date.now()) {
  // the server sends UTC timestamps without a zone marker; read them as UTC, not as the browser's local time
  const t = typeof ts === 'number' ? ts : new Date(typeof ts === 'string' && !/[zZ]|[+-]\d\d:?\d\d$/.test(ts) ? ts + 'Z' : ts).getTime()
  if (!t || Number.isNaN(t)) return ''
  const s = Math.max(0, Math.round((now - t) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}
