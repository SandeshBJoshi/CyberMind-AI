import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'
import './console.css'

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }
  componentDidCatch(error, info) {
    console.error('Captured UI error:', error, info)
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 40, color: '#ff3b5c', fontFamily: 'monospace', background: '#050a08', minHeight: '100vh' }}>
          <h2 style={{ fontFamily: 'var(--font-display, sans-serif)' }}>CYBERMIND AI Application Alert</h2>
          <p style={{ color: '#ffcb47' }}>A component error was caught safely:</p>
          <pre style={{ whiteSpace: 'pre-wrap', color: '#eafff2', background: 'rgba(255,255,255,0.05)', padding: 16, borderRadius: 8 }}>
            {String(this.state.error?.message || this.state.error)}
          </pre>
          <button
            onClick={() => { window.localStorage.removeItem('vaultapp_session'); window.location.reload() }}
            style={{ padding: '10px 20px', background: '#39ff94', color: '#000', fontWeight: 'bold', border: 'none', borderRadius: 6, cursor: 'pointer', marginTop: 16 }}
          >
            Reset Session & Reload
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
)
