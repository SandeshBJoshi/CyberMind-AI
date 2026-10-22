import { getAdminToken, API_BASE } from './api'

// The live feed is admin-only: the token travels in the query string (browsers cannot set WebSocket headers).
export function connectLiveFeed(onMessage) {
  let ws
  let closedByUser = false
  let timer

  function connect() {
    const token = getAdminToken()
    if (!token) return                                  // not signed in yet; the caller reconnects after login
    ws = new WebSocket(`${API_BASE.replace(/^http/, 'ws')}/ws/live?token=${encodeURIComponent(token)}`)
    ws.onmessage = (evt) => {
      try {
        onMessage(JSON.parse(evt.data))
      } catch {
        // ignore malformed frames
      }
    }
    ws.onclose = (e) => {
      if (closedByUser || e.code === 4401) return        // 4401 = rejected (token missing / expired): do not hammer the server
      timer = setTimeout(connect, 2000)
    }
  }
  connect()

  return () => {
    closedByUser = true
    clearTimeout(timer)
    if (ws) ws.close()
  }
}
