export const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000'

function store(key) {
  try { return window.localStorage.getItem(key) } catch { return null }
}

function currentPublicIp() {
  return store('vault_public_ip')
}

function authHeaders() {
  const token = store('cybermind_token') || store('sentinel_token')
  return token ? { Authorization: 'Bearer ' + token } : {}
}

// Development only: the backend ignores this header unless ALLOW_CLIENT_IP_HEADER=true (a client can forge it).
function clientIpHeaders() {
  const ip = currentPublicIp()
  return ip ? { 'X-Forwarded-For': ip, 'X-Real-IP': ip } : {}
}

// ---- signed session tokens: knowing a session id is not enough to report events for it ----
function sessionTokens() {
  try { return JSON.parse(store('cm_session_tokens') || '{}') } catch { return {} }
}
function rememberSessionToken(sessionId, token) {
  if (!sessionId || !token) return
  try {
    const all = sessionTokens(); all[sessionId] = token
    const keys = Object.keys(all); if (keys.length > 50) delete all[keys[0]]
    window.localStorage.setItem('cm_session_tokens', JSON.stringify(all))
  } catch {}
}
function sessionHeaders(sessionId) {
  const t = sessionTokens()[sessionId]
  return t ? { 'X-Session-Token': t } : {}
}

// Admin API call: attaches the token; if the server says it expired, tell the app to sign the user out.
async function adminFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers: { ...(options.headers || {}), ...authHeaders() } })
  if (res.status === 401 && authHeaders().Authorization) window.dispatchEvent(new Event('cm-session-expired'))
  return res
}
const json = (body) => ({ headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

export async function login(username, password) {
  const res = await fetch(`${API_BASE}/auth/login`, { method: 'POST', ...json({ username, password }) })
  if (res.status === 429) {
    const wait = res.headers.get('Retry-After')
    throw new Error(`Too many attempts. Try again${wait ? ` in ${wait}s` : ' later'}.`)
  }
  if (!res.ok) throw new Error('Invalid credentials')
  const data = await res.json()
  window.localStorage.setItem('cybermind_token', data.access_token)
  window.localStorage.setItem('sentinel_token', data.access_token)
  return data
}

export function logout() {
  const h = authHeaders()
  if (h.Authorization) fetch(`${API_BASE}/auth/logout`, { method: 'POST', headers: h }).catch(() => {})   // revoke the token server-side
  window.localStorage.removeItem('cybermind_token')
  window.localStorage.removeItem('sentinel_token')
}

export function isAuthed() {
  return !!(store('cybermind_token') || store('sentinel_token'))
}

export function getAdminToken() {
  return store('cybermind_token') || store('sentinel_token')
}

// ---------------------------------------------------------------- sessions and telemetry
export async function startSession(user_label) {
  const res = await adminFetch('/api/sessions/start', { method: 'POST', ...json({ user_label }), headers: { 'Content-Type': 'application/json' } })
  if (!res.ok) throw new Error('Could not create a session')
  const data = await res.json()
  rememberSessionToken(data.session_id, data.session_token)
  return data
}

export async function createUserSession(user_label, ip_address, device_info) {
  const res = await fetch(`${API_BASE}/user/session`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...clientIpHeaders() },
    body: JSON.stringify({ user_label, ip_address, device_info }),
  })
  if (!res.ok) throw new Error('Unable to start VaultApp session')
  const data = await res.json()
  rememberSessionToken(data.session_id, data.session_token)
  return data
}

export async function sendUserBehavior(payload) {
  const res = await fetch(`${API_BASE}/user/behavior`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...clientIpHeaders(), ...sessionHeaders(payload.session_id) },
    body: JSON.stringify(payload),
  })
  const data = await res.json().catch(() => ({}))
  return { ok: res.ok, status: res.status, data }
}

export async function sendApiRequest(payload) {
  const res = await adminFetch('/user/behavior', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      session_id: payload.session_id,
      event_type: 'api_call',
      ip_address: payload.ip_address,
      device_info: payload.device_info,
      extra: { target_endpoint: payload.endpoint, technique: 'T1499-API-Request-Burst' },
    }),
  })
  const data = await res.json().catch(() => ({}))
  return { ok: res.ok, status: res.status, data }
}

export async function fetchClientIp() {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), 2000)
  try {
    const res = await fetch('https://api.ipify.org?format=json', { signal: controller.signal })
    clearTimeout(timeoutId)
    if (res.ok) {
      const data = await res.json()
      if (data?.ip) {
        try { window.localStorage.setItem('vault_public_ip', data.ip) } catch {}
        return data.ip
      }
    }
  } catch {}

  try {
    const res = await fetch(`${API_BASE}/user/my-ip`)
    if (res.ok) {
      const data = await res.json()
      if (data?.ip) {
        try { window.localStorage.setItem('vault_public_ip', data.ip) } catch {}
        return data.ip
      }
    }
  } catch {}

  const cached = store('vault_public_ip')
  return cached || '127.0.0.1'
}

export async function getUserStatus(sessionId) {
  const res = await fetch(`${API_BASE}/user/status/${sessionId}`, { headers: { ...clientIpHeaders(), ...sessionHeaders(sessionId) } })
  if (!res.ok) throw new Error('Unable to retrieve session status')
  return res.json()
}

export async function getSessions() {
  const res = await adminFetch('/api/sessions')
  if (!res.ok) throw new Error('Failed to load sessions')
  return res.json()
}

export async function getLogs(params = {}) {
  const qs = new URLSearchParams(params).toString()
  const res = await adminFetch(`/api/logs?${qs}`)
  if (!res.ok) throw new Error('Failed to load logs')
  return res.json()
}

export async function getLockdowns() {
  const res = await adminFetch('/api/logs/lockdowns')
  if (!res.ok) throw new Error('Failed to load lockdowns')
  return res.json()
}

export async function downloadLogs(format = 'csv') {
  const res = await adminFetch(`/api/logs/export?format=${format}`)
  if (!res.ok) throw new Error('Export failed')
  const blob = await res.blob()
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `cybermind-events.${format === 'csv' ? 'csv' : 'jsonl'}`
  a.click()
  URL.revokeObjectURL(a.href)
}

export async function unlockSession(session_id) {
  const res = await adminFetch('/api/lockdown/unlock', { method: 'POST', ...json({ session_id }) })
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Unlock failed')
  return res.json()
}

export async function clearStepUp(session_id) {
  const res = await adminFetch(`/api/sessions/${session_id}/step-up/clear`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Could not clear step-up')
  return res.json()
}

export async function protectedAction(session_id, action) {
  const res = await adminFetch('/api/protected-action', {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...sessionHeaders(session_id) }, body: JSON.stringify({ session_id, action }),
  })
  const data = await res.json().catch(() => ({}))
  return { ok: res.ok, status: res.status, data }
}

export async function startNormalTraffic() {
  const res = await adminFetch('/api/simulate/start-normal', { method: 'POST' })
  if (!res.ok) throw new Error('Could not start the simulation')
  return res.json()
}

export async function stopNormalTraffic() {
  const res = await adminFetch('/api/simulate/stop-normal', { method: 'POST' })
  if (!res.ok) throw new Error('Could not stop the simulation')
  return res.json()
}

export async function execIdentityChurn(payload) {
  const res = await adminFetch('/api/simulate/manual/identity-churn', { method: 'POST', ...json(payload) })
  return res.json()
}

// ---------------------------------------------------------------- login protection: campaigns, decoys, lab
async function getJson(path, fail) {
  const res = await adminFetch(path)
  if (!res.ok) throw new Error(fail)
  return res.json()
}
export const getCampaigns = () => getJson('/api/campaigns', 'Failed to load campaigns')
export const getRecentAttempts = () => getJson('/api/auth-events/recent?limit=60', 'Failed to load login attempts')
export const getDecoys = () => getJson('/api/decoys', 'Failed to load decoy accounts')
export const getSecurityStatus = () => getJson('/api/security/status', 'Failed to load security status')
export const getMlStatus = () => getJson('/api/ml/status', 'Failed to load model status')
export const getLabScenarios = () => getJson('/api/lab/scenarios', 'Failed to load lab scenarios')
export const getLabResults = () => getJson('/api/lab/results', 'Failed to load lab results')

export async function releaseCampaign(id) {
  const res = await adminFetch(`/api/campaigns/${id}/release`, { method: 'POST' })
  if (!res.ok) throw new Error('Could not release campaign')
  return res.json()
}
export async function addDecoy(username, note) {
  const res = await adminFetch('/api/decoys', { method: 'POST', ...json({ username, note }) })
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Could not add decoy')
  return res.json()
}
export async function deleteDecoy(username) {
  const res = await adminFetch(`/api/decoys/${encodeURIComponent(username)}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Could not remove decoy')
  return res.json()
}
export async function runLab(scenarios, scale = 0.5) {
  const res = await adminFetch('/api/lab/run', { method: 'POST', ...json({ scenarios, scale }) })
  if (!res.ok) throw new Error('Could not start the lab')
  return res.json()
}
export async function retrainModel() {
  const res = await adminFetch('/api/ml/retrain', { method: 'POST' })
  if (!res.ok) throw new Error('Retrain failed')
  return res.json()
}

// ---------------------------------------------------------------- CyberMind Intel
async function cybermindRequest(path, options = {}) {
  const res = await adminFetch(`/api/cybermind${path}`, options)
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(body.detail || 'CYBERMIND AI request failed')
  return body
}

export function getCybermindStatus() {
  return cybermindRequest('/status')
}

export function ingestCybermindReport(file) {
  const form = new FormData()
  form.append('file', file)
  return cybermindRequest('/ingest', { method: 'POST', body: form })
}

export function queryCybermind(payload) {
  return cybermindRequest('/query', { method: 'POST', ...json(payload) })
}

export function clearCybermindStore() {
  return cybermindRequest('/clear', { method: 'POST' })
}

// ---------------------------------------------------------------- VaultApp (the protected demo bank)
async function bankCall(path, { method = 'POST', body, sessionId } = {}) {
  const res = await fetch(`${API_BASE}/bank${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...clientIpHeaders(), ...(sessionId ? sessionHeaders(sessionId) : {}) },
    body: body ? JSON.stringify(body) : undefined,
  })
  const data = await res.json().catch(() => ({}))
  const detail = typeof data.detail === 'string' ? data.detail : Array.isArray(data.detail) ? data.detail.map(d => d.msg).join(', ') : ''
  return { ok: res.ok, status: res.status, data, detail }
}
export async function bankRegister(username, full_name, password) {
  return bankCall('/register', { body: { username, full_name, password } })
}
export async function bankLogin(username, password, device_info) {
  const r = await bankCall('/login', { body: { username, password, device_info } })
  if (r.ok) rememberSessionToken(r.data.session_id, r.data.session_token)
  return r
}
export const bankAccount = (sessionId) => bankCall(`/account?session_id=${encodeURIComponent(sessionId)}`, { method: 'GET', sessionId })
export const bankTransfer = (sessionId, recipient, amount, memo) => bankCall('/transfer', { body: { session_id: sessionId, recipient, amount, memo }, sessionId })
export const bankDismissNotice = (sessionId) => bankCall('/notice/dismiss', { body: { session_id: sessionId }, sessionId })
export const bankStepUp = (sessionId, password) => bankCall('/step-up/verify', { body: { session_id: sessionId, password }, sessionId })

// ---------------------------------------------------------------- Shadow mode (Feature 2)
export const getShadowQueue = () => getJson('/api/shadow', 'Failed to load the shadow queue')
export const getShadowDetail = (sid) => getJson(`/api/shadow/${sid}`, 'Failed to load the shadow case')
async function shadowAct(sid, kind) {
  const res = await adminFetch(`/api/shadow/${sid}/${kind}`, { method: 'POST' })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Could not ${kind}`)
  return data
}
export const releaseShadow = (sid) => shadowAct(sid, 'release')
export const confirmShadow = (sid) => shadowAct(sid, 'confirm')

// ---------------------------------------------------------------- Poison tracing (Feature 1)
export const getPoisonList = (analysisId) => getJson('/api/poison' + (analysisId ? `?analysis_id=${analysisId}` : ''), 'Failed to load poison traces')
export const getPoisonDetail = (id) => getJson(`/api/poison/${id}`, 'Failed to load the trace')
export async function mintPoison(analysisId) {
  const res = await adminFetch('/api/poison/mint', { method: 'POST', ...json({ analysis_id: analysisId }) })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Could not plant a credential')
  return data
}
export async function retirePoison(id) {
  const res = await adminFetch(`/api/poison/${id}/retire`, { method: 'POST' })
  if (!res.ok) throw new Error('Could not retire the credential')
  return res.json()
}

// ---------------------------------------------------------------- Email (phishing) analysis
export const getEmailSamples = () => getJson('/api/email/samples', 'Failed to load sample emails')
export const getEmailHistory = () => getJson('/api/email/history?limit=40', 'Failed to load email history')
export const getEmailStats = () => getJson('/api/email/stats', 'Failed to load email stats')
export const getEmailAnalysis = (id) => getJson(`/api/email/${id}`, 'Failed to load the analysis')

async function emailPost(path, options, fail) {
  const res = await adminFetch(path, { method: 'POST', ...options })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : Array.isArray(data.detail) ? data.detail.map(d => d.msg).join(', ') : fail)
  return data
}
export const getEmailAiStatus = () => getJson('/api/email/ai-status', 'Failed to load AI status')
export const analyzeEmailFile = (file, o = {}) => { const f = new FormData(); f.append('file', file); f.append('ai', o.ai ? 'true' : 'false'); if (o.model) f.append('model', o.model); return emailPost('/api/email/analyze', { body: f }, 'Could not analyse that file') }
export const analyzeEmailText = (text, o = {}) => emailPost('/api/email/analyze-text', json({ text, ai: !!o.ai, model: o.model || null }), 'Could not analyse that text')
export const analyzeEmailSample = (name, o = {}) => emailPost('/api/email/analyze-sample', json({ name, ai: !!o.ai, model: o.model || null }), 'Could not analyse that sample')

export async function deleteEmailAnalysis(id) {
  const res = await adminFetch(`/api/email/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Could not delete the analysis')
  return res.json()
}

export async function downloadEmailReport(id, format = 'pdf') {
  const res = await adminFetch(`/api/email/${id}/report?format=${format}`)
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Could not build the report')
  const blob = await res.blob()
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `phishing-report-${id}.${format}`
  a.click()
  URL.revokeObjectURL(a.href)
}

export const getNetworkStatus = () => getJson('/api/network/status', 'Failed to load the network status')
export const getAdaptiveResults = () => getJson('/api/lab/adaptive/results', 'Failed to load the stress test')
export async function runAdaptive() {
  const res = await adminFetch('/api/lab/adaptive/run', { method: 'POST', ...json({}) })
  if (!res.ok) throw new Error('Could not start the stress test')
  return res.json()
}
