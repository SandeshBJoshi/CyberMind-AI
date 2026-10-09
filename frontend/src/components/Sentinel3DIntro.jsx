import { useEffect, useRef, useState } from 'react'
import './Sentinel3DIntro.css'

// ─── TIMELINE (matches reference storyboard, all in ms) ────────────
const T = {
  // 00:00 - 00:02: Dark screen with glitch text
  PHASE1_START: 0,
  PHASE1_TEXT: 'INITIALIZING SYSTEM...',

  // 00:02 - 00:04: Glitch effects, code fragments
  PHASE2_START: 2200,
  PHASE2_TEXT: 'SCANNING ENVIRONMENT...',

  // 00:04 - 00:08: Glitch particles forming text ("SENTINEL")
  ASSEMBLE_START: 4200,

  // 00:08 - 00:12: Glitch stabilization ("SENTINEL AI")
  STABILIZE_START: 8200,

  // 00:12 - 00:16: Logo lock with shock effect + "DETECT · ANALYZE · PROTECT"
  LOGO_LOCK: 12200,

  // 00:16 - 00:20: Tagline with visual effects ("SECURING A SAFER TOMORROW" + Cyber Globe)
  TAGLINE_GLOBE: 16200,

  // 00:20 - 00:24: Final reveal with light shock + vertical pillar + "SYSTEM ONLINE"
  LIGHT_SHOCK: 20200,

  // 00:24 - 00:26: Hold for a moment
  HOLD_START: 24200,

  // 00:26 - 00:27+: Dashboard loads underneath / fade begins
  FADE_START: 26200,
  FADE_DUR: 1000,

  // 00:27.2+: Complete
  DURATION: 27200,
}

const RAIN_CHARS = '01ΩΨΣΔΦΘΓΛΞ⎕∂∫░▒▓█⌥⌘⚡#$%&@!2389ABCDEF'.split('')

const TERMINAL_LOGS = [
  'INITIALIZING SYSTEM...',
  'SCANNING ENVIRONMENT...',
  'SECURITY PROTOCOL V4.2.1 [STANDBY]',
  'SYNCHRONIZING THREAT INTELLIGENCE MATRIX...',
  'DEEP NEURAL HEURISTICS ENGINE LOADED',
  'CYBERMIND CORE ENGAGED — SYSTEM SECURE',
]

export default function Sentinel3DIntro({ onComplete, onFadeStart }) {
  const canvasRef = useRef(null)
  const doneRef = useRef(false)
  const onFadeStartRef = useRef(onFadeStart)
  onFadeStartRef.current = onFadeStart

  const [fading, setFading] = useState(false)
  const [phaseNum, setPhaseNum] = useState(1) // 1 to 10
  const [progress, setProgress] = useState(0)
  const [activeLog, setActiveLog] = useState(TERMINAL_LOGS[0])
  const [showTaglineSecuring, setShowTaglineSecuring] = useState(false)
  const [showDetectTagline, setShowDetectTagline] = useState(false)
  const [showSystemOnline, setShowSystemOnline] = useState(false)
  const [showHUD, setShowHUD] = useState(false)

  const doSkip = () => {
    if (doneRef.current) return
    doneRef.current = true
    setFading(true)
    onFadeStartRef.current?.()
    setTimeout(() => {
      onComplete?.()
    }, 900)
  }

  useEffect(() => {
    // Accessibility: instant skip if prefers-reduced-motion
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      const t = setTimeout(() => {
        setFading(true)
        setTimeout(onComplete, 300)
      }, 400)
      return () => clearTimeout(t)
    }

    const canvas = canvasRef.current
    if (!canvas) return

    let mounted = true
    let animId = null
    const removers = []

    const ctx = canvas.getContext('2d', { alpha: true })

    let W = window.innerWidth
    let H = window.innerHeight
    const DPR = Math.min(window.devicePixelRatio || 1, 2)

    const resizeCanvas = () => {
      W = window.innerWidth
      H = window.innerHeight
      canvas.width = W * DPR
      canvas.height = H * DPR
      canvas.style.width = W + 'px'
      canvas.style.height = H + 'px'
      ctx.scale(DPR, DPR)
    }
    resizeCanvas()
    window.addEventListener('resize', resizeCanvas)
    removers.push(() => window.removeEventListener('resize', resizeCanvas))

    // Mouse parallax
    let mx = W / 2, my = H / 2
    const onMM = (e) => { mx = e.clientX; my = e.clientY }
    window.addEventListener('mousemove', onMM)
    removers.push(() => window.removeEventListener('mousemove', onMM))

    // Keyboard skip
    const onKey = (e) => { if (e.key === 'Escape' || e.key === ' ') doSkip() }
    window.addEventListener('keydown', onKey)
    removers.push(() => window.removeEventListener('keydown', onKey))

    // Helpers
    const clamp = (v, min, max) => Math.max(min, Math.min(max, v))
    const lerp = (a, b, t) => a + (b - a) * t
    const easeOutExpo = (t) => t >= 1 ? 1 : 1 - Math.pow(2, -10 * t)
    const smoothstep = (t) => t * t * (3 - 2 * t)

    const init = () => {
      if (!mounted) return

      // 1. Offscreen sample for "SENTINEL" and "AI"
      const offscreen = document.createElement('canvas')
      offscreen.width = W
      offscreen.height = H
      const oc = offscreen.getContext('2d')

      const fontSize = clamp(Math.round(W * 0.068), 38, 88)
      oc.fillStyle = '#fff'
      oc.font = `900 ${fontSize}px 'Orbitron', 'JetBrains Mono', monospace`
      oc.textAlign = 'center'
      oc.textBaseline = 'middle'

      // First measure and record CYBERMIND vs AI positions
      const fullText = 'CYBERMIND AI'
      oc.fillText(fullText, W / 2, H / 2)

      const pxData = oc.getImageData(0, 0, W, H).data
      const step = Math.max(3, Math.round(W / 260))
      const rawPoints = []
      for (let y = 0; y < H; y += step) {
        for (let x = 0; x < W; x += step) {
          if (pxData[(y * W + x) * 4 + 3] > 60) {
            // Check if this pixel is part of "SENTINEL" (left ~75%) or "AI" (right ~25%)
            rawPoints.push([x, y])
          }
        }
      }

      const MAX_P = 1350
      const chosen = rawPoints.length > MAX_P
        ? rawPoints.sort(() => Math.random() - 0.5).slice(0, MAX_P)
        : rawPoints

      const rightEdge = chosen.reduce((m, [x]) => Math.max(m, x), 0)
      const leftEdge = chosen.reduce((m, [x]) => Math.min(m, x), W)
      const textSpan = rightEdge - leftEdge || 1

      const particles = chosen.map(([tx, ty]) => {
        const r = Math.random()
        const a = Math.random() * Math.PI * 2
        const d = Math.random() * Math.max(W, H) * 0.7 + 90
        return {
          tx, ty,
          x0: W / 2 + Math.cos(a) * d,
          y0: H / 2 + Math.sin(a) * d,
          cx: 0, cy: 0,
          localT: 0,
          delay: ((tx - leftEdge) / textSpan) * 0.28 + Math.random() * 0.22,
          size: r < 0.12 ? 2.5 : r < 0.45 ? 1.6 : 1.1,
          shimmer: Math.random() * Math.PI * 2,
          colorType: r < 0.65 ? 'cyan' : r < 0.88 ? 'neon' : 'white',
        }
      })

      // 2. Code Rain Columns
      const numCols = Math.ceil(W / 18)
      const rainCols = Array.from({ length: numCols }, (_, i) => ({
        x: i * 18 + 9,
        y: -Math.random() * H * 0.8,
        speed: Math.random() * 8 + 6,
        trail: Array.from({ length: 16 }, () => RAIN_CHARS[Math.floor(Math.random() * RAIN_CHARS.length)]),
        upTimer: 0,
        alpha: Math.random() * 0.28 + 0.08,
      }))

      // 3. Shockwave Pool
      const shockWaves = []
      const triggerWave = (color, spd, maxRMul, lw = 3) => {
        shockWaves.push({
          born: performance.now(),
          color,
          spd,
          r: 0,
          maxR: Math.max(W, H) * maxRMul,
          x: W / 2,
          y: H / 2,
          lw,
        })
      }

      // 4. Cyber Globe Wireframe Points for Phase 6 (00:16 - 00:20)
      const globeRadius = Math.min(W, H) * 0.22
      const globeDots = []
      const rings = 12
      const dotsPerRing = 24
      for (let i = 0; i < rings; i++) {
        const phi = (Math.PI * (i + 1)) / (rings + 1)
        for (let j = 0; j < dotsPerRing; j++) {
          const theta = (2 * Math.PI * j) / dotsPerRing
          globeDots.push({
            x: Math.sin(phi) * Math.cos(theta),
            y: Math.cos(phi),
            z: Math.sin(phi) * Math.sin(theta),
          })
        }
      }

      let glitch = 0
      let shakeX = 0, shakeY = 0
      let lastT = performance.now()
      const startT = lastT
      let triggeredLogoShock = false
      let triggeredFinalShock = false

      function render(now) {
        if (!mounted) return
        const dt = Math.min(now - lastT, 50)
        lastT = now
        const elapsed = now - startT

        // ── Step management & HUD updates ────────────────────────────
        setProgress(Math.round(clamp((elapsed / T.FADE_START) * 100, 0, 100)))

        if (elapsed < T.PHASE2_START) {
          setPhaseNum(1)
          setActiveLog('INITIALIZING SYSTEM...')
          setShowDetectTagline(false)
          setShowTaglineSecuring(false)
          setShowSystemOnline(false)
          setShowHUD(false)
        } else if (elapsed < T.ASSEMBLE_START) {
          setPhaseNum(2)
          setActiveLog('SCANNING ENVIRONMENT...')
        } else if (elapsed < T.STABILIZE_START) {
          setPhaseNum(3)
          setActiveLog('ASSEMBLING QUANTUM NEURAL CORE...')
        } else if (elapsed < T.LOGO_LOCK) {
          setPhaseNum(4)
          setActiveLog('STABILIZING CYBERMIND MATRIX...')
        } else if (elapsed < T.TAGLINE_GLOBE) {
          setPhaseNum(5)
          setActiveLog('SECURITY SIGNATURE LOCKED')
          setShowDetectTagline(true)
          setShowTaglineSecuring(false)
          setShowHUD(true)
          if (!triggeredLogoShock) {
            triggeredLogoShock = true
            triggerWave('0,240,255', 4.8, 0.9, 3.5)
            triggerWave('255,59,92', 3.6, 0.65, 2.5)
            triggerWave('57,255,148', 2.8, 0.45, 2)
          }
        } else if (elapsed < T.LIGHT_SHOCK) {
          setPhaseNum(6)
          setActiveLog('SECURING A SAFER TOMORROW...')
          setShowDetectTagline(false)
          setShowTaglineSecuring(true)
        } else if (elapsed < T.HOLD_START) {
          setPhaseNum(7)
          setActiveLog('CYBERMIND AI: SYSTEM ONLINE')
          setShowTaglineSecuring(false)
          setShowSystemOnline(true)
          if (!triggeredFinalShock) {
            triggeredFinalShock = true
            triggerWave('255,255,255', 5.6, 1.2, 4)
            triggerWave('0,240,255', 4.2, 0.95, 3)
            triggerWave('57,255,148', 3.4, 0.7, 2.5)
          }
        } else if (elapsed < T.FADE_START) {
          setPhaseNum(8)
          setActiveLog('SYNCHRONIZATION NOMINAL — HOLDING')
        } else {
          setPhaseNum(9)
          setActiveLog('ENGAGING ACTIVE DASHBOARD...')
          if (!fading) {
            setFading(true)
            onFadeStartRef.current?.()
          }
        }

        if (elapsed >= T.DURATION && !doneRef.current) {
          doneRef.current = true
          onComplete?.()
          return
        }

        // ── Glitch Calculation ───────────────────────────────────────
        // vibeT: 1.0 during phase1/2 boot text, 0→1 during particle formation,
        //        1→0 as it settles, then 0 after logo lock (text locked crisp)
        const vibeT = elapsed < T.PHASE1_START
          ? 0
          : elapsed < T.ASSEMBLE_START
            ? 1.0  // full shock during INITIALIZING + SCANNING phases
            : elapsed < T.STABILIZE_START
              ? clamp((elapsed - T.ASSEMBLE_START) / (T.STABILIZE_START - T.ASSEMBLE_START), 0, 1)
              : elapsed < T.LOGO_LOCK
                ? 1 - clamp((elapsed - T.STABILIZE_START) / (T.LOGO_LOCK - T.STABILIZE_START), 0, 1)
                : 0

        let targetGlitch = 0.02
        if (elapsed < T.PHASE2_START) {
          // INITIALIZING SYSTEM — steady rumble like rocket ignition building up
          targetGlitch = 0.32 + Math.sin(elapsed * 0.018) * 0.08
        } else if (elapsed < T.ASSEMBLE_START) {
          // SCANNING ENVIRONMENT — rumble peaks, steady sustained power
          targetGlitch = 0.42 + Math.sin(elapsed * 0.014) * 0.08
        } else if (elapsed < T.STABILIZE_START) {
          // Full shock during particle assembly
          targetGlitch = 1.0
        } else if (elapsed < T.LOGO_LOCK) {
          // Smooth power-down to zero
          targetGlitch = lerp(0.95, 0.0, smoothstep(clamp((elapsed - T.STABILIZE_START) / (T.LOGO_LOCK - T.STABILIZE_START), 0, 1)))
        } else if (elapsed < T.TAGLINE_GLOBE) {
          const dl = elapsed - T.LOGO_LOCK
          targetGlitch = dl < 250 ? 0.55 : 0.03
        } else if (elapsed < T.LIGHT_SHOCK) {
          targetGlitch = 0.02 + (Math.sin(elapsed * 0.003) * 0.01)
        } else if (elapsed < T.HOLD_START) {
          const ds = elapsed - T.LIGHT_SHOCK
          targetGlitch = ds < 300 ? 0.9 : 0.04
        } else {
          targetGlitch = 0.01
        }
        glitch += (targetGlitch - glitch) * 0.10

        // Screen shake — low-freq steady rumble during boot, powerful during particle assembly
        const shakeAmt = vibeT > 0
          ? vibeT * glitch * 10
          : (glitch > 0.55 ? glitch * 7 : 0)
        shakeX = lerp(shakeX, (Math.random() - 0.5) * shakeAmt, 0.35)
        shakeY = lerp(shakeY, (Math.random() - 0.5) * shakeAmt * 0.45, 0.35)

        // Fade multiplier
        const fadeRaw = elapsed >= T.FADE_START ? clamp((elapsed - T.FADE_START) / T.FADE_DUR, 0, 1) : 0
        const fadeMult = 1 - smoothstep(fadeRaw)

        // ── DRAW PASSES ──────────────────────────────────────────────
        ctx.save()
        ctx.translate(shakeX, shakeY)
        // Clear transparently so particle background continues behind
        ctx.clearRect(-20, -20, W + 40, H + 40)

        // Radial cyber atmosphere
        const radialGrad = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, Math.min(W, H) * 0.65)
        radialGrad.addColorStop(0, `rgba(0, 240, 255, ${0.055 * fadeMult})`)
        radialGrad.addColorStop(0.4, `rgba(57, 255, 148, ${0.035 * fadeMult})`)
        radialGrad.addColorStop(1, 'rgba(2, 6, 12, 0)')
        ctx.fillStyle = radialGrad
        ctx.fillRect(0, 0, W, H)

        // Random signal blackout flash
        if (glitch > 0.6 && (elapsed % 700) < 45) {
          ctx.fillStyle = `rgba(0, 0, 0, ${0.85 * fadeMult})`
          ctx.fillRect(-20, -20, W + 40, H + 40)
        }

        // ── PERSPECTIVE GROUND CYBER GRID (Phases 1-4 and 7-9) ─────────
        const gridAlpha = (elapsed < T.ASSEMBLE_START || elapsed >= T.LIGHT_SHOCK)
          ? 0.08 * fadeMult
          : 0.02 * fadeMult
        if (gridAlpha > 0.005) {
          ctx.strokeStyle = `rgba(0, 240, 255, ${gridAlpha})`
          ctx.lineWidth = 0.6
          const horizonY = H * 0.68
          const vpx = W / 2 + (mx - W / 2) * 0.02
          for (let xi = -12; xi <= 12; xi++) {
            const gx = W / 2 + xi * (W / 14)
            ctx.beginPath()
            ctx.moveTo(gx, H)
            ctx.lineTo(vpx, horizonY)
            ctx.stroke()
          }
          for (let yi = 1; yi <= 6; yi++) {
            const gy = horizonY + (H - horizonY) * Math.pow(yi / 6, 1.8)
            ctx.beginPath()
            ctx.moveTo(0, gy)
            ctx.lineTo(W, gy)
            ctx.stroke()
          }
        }

        // ── CODE RAIN (Phases 1 to 5) ────────────────────────────────
        const showRain = elapsed >= T.PHASE1_START && elapsed < T.TAGLINE_GLOBE
        if (showRain && fadeMult > 0.05) {
          const rainFade = elapsed < T.LOGO_LOCK ? 1 : lerp(1, 0, (elapsed - T.LOGO_LOCK) / (T.TAGLINE_GLOBE - T.LOGO_LOCK))
          ctx.font = '12px "JetBrains Mono", monospace'
          rainCols.forEach((col) => {
            col.y += col.speed * (dt / 16)
            if (col.y > H + 180) {
              col.y = -Math.random() * 100
              col.speed = Math.random() * 8 + 5
            }
            col.upTimer += dt
            if (col.upTimer > 150) {
              col.upTimer = 0
              const ci = Math.floor(Math.random() * col.trail.length)
              col.trail[ci] = RAIN_CHARS[Math.floor(Math.random() * RAIN_CHARS.length)]
            }
            col.trail.forEach((ch, ci) => {
              const cy = col.y - ci * 15
              if (cy < -15 || cy > H + 15) return
              const ta = (ci === 0 ? 0.85 : (1 - ci / 15) * 0.32) * col.alpha * rainFade * fadeMult
              if (ta < 0.01) return
              ctx.fillStyle = ci === 0 ? `rgba(220,255,245,${ta})` : `rgba(57,255,148,${ta})`
              ctx.fillText(ch, col.x, cy)
            })
          })
        }

        // ── PHASE 1 & 2 TERMINAL GLITCH CENTER TEXT ──────────────────
        if (elapsed < T.ASSEMBLE_START && fadeMult > 0.08) {
          const textPhase = elapsed < T.PHASE2_START ? 'INITIALIZING SYSTEM...' : 'SCANNING ENVIRONMENT...'
          const tfs = clamp(Math.round(W * 0.028), 18, 36)
          ctx.font = `700 ${tfs}px "Orbitron", monospace`
          ctx.textAlign = 'center'
          ctx.textBaseline = 'middle'

          const t = elapsed * 0.001
          // Low-frequency sine rumble — rocket launch feel, not chaotic jitter
          const rumbleX = Math.sin(t * 22 + 0.4) * glitch * 5
          const rumbleY = Math.cos(t * 17 + 1.1) * glitch * 2.5

          // Subtle chromatic split that scales with rumble
          const split = glitch * 5
          ctx.fillStyle = `rgba(255, 50, 80, ${0.45 * glitch * fadeMult})`
          ctx.fillText(textPhase, W / 2 + split, H / 2 - 1)
          ctx.fillStyle = `rgba(0, 220, 255, ${0.45 * glitch * fadeMult})`
          ctx.fillText(textPhase, W / 2 - split, H / 2 + 1)

          // Main text riding the rumble
          ctx.fillStyle = `rgba(220, 255, 245, ${0.95 * fadeMult})`
          ctx.fillText(textPhase, W / 2 + rumbleX, H / 2 + rumbleY)
        }

        // ── PHASE 3, 4, 5, 7, 8: SENTINEL AI PARTICLE MATRIX ─────────
        const showParticles = (elapsed >= T.ASSEMBLE_START && elapsed < T.TAGLINE_GLOBE) || (elapsed >= T.LIGHT_SHOCK)
        if (showParticles && fadeMult > 0.04) {
          const assembleProg = elapsed < T.STABILIZE_START
            ? clamp((elapsed - T.ASSEMBLE_START) / (T.STABILIZE_START - T.ASSEMBLE_START), 0, 1)
            : 1

          // Particle positions: animate both SENTINEL and AI together
          particles.forEach((p) => {
            const lt = clamp((assembleProg - p.delay * 0.4) / (1 - p.delay * 0.4 + 0.001), 0, 1)
            p.localT = lt
            if (lt <= 0) return
            const e = easeOutExpo(lt)
            p.cx = p.x0 + (p.tx - p.x0) * e
            p.cy = p.y0 + (p.ty - p.y0) * e
          })

          // ── Chromatic Aberration — active throughout formation AND settle ──
          if (vibeT > 0 && glitch > 0.06) {
            const ca = glitch * vibeT * 14   // shrinks as text settles
            ctx.globalCompositeOperation = 'screen'
            particles.forEach((p) => {
              if (p.localT <= 0) return
              const a = Math.min(1, p.localT * 1.5) * fadeMult * 0.42 * glitch * vibeT
              if (a < 0.01) return
              ctx.fillStyle = `rgba(255, 35, 70, ${a})`
              ctx.fillRect(p.cx + ca, p.cy, p.size, p.size)
              ctx.fillStyle = `rgba(0, 110, 255, ${a})`
              ctx.fillRect(p.cx - ca, p.cy, p.size, p.size)
            })
            ctx.globalCompositeOperation = 'source-over'
          }

          // ── Main Particle Render ──────────────────────────────────────
          particles.forEach((p) => {
            if (p.localT <= 0) return
            let dx, dy

            if (elapsed >= T.LOGO_LOCK) {
              // Fully locked — pixel-perfect, zero movement
              dx = p.tx
              dy = p.ty
            } else {
              // Base interpolated position
              dx = p.cx
              dy = p.cy

              if (vibeT > 0 && glitch > 0.04) {
                // Hard electronic shock: two independent high-freq sine waves per particle
                // Amplitude = full power during assembly, decays as text settles (vibeT → 0)
                const shockScale = glitch * vibeT
                const t = elapsed * 0.001   // time in seconds

                // Each particle has a unique frequency fingerprint via shimmer
                const freqA = 28 + p.shimmer * 6   // ~28–47 Hz range
                const freqB = 41 + p.shimmer * 9

                // Hard X displacement: square-ish clipped sine for digital feel
                const rawX = Math.sin(freqA * t + p.shimmer * 3.7)
                const rawY = Math.sin(freqB * t + p.shimmer * 2.1)

                // Add a faster, smaller jitter on top
                const jX = Math.sin(freqA * 3.1 * t + p.shimmer) * 0.35
                const jY = Math.cos(freqB * 2.7 * t + p.shimmer) * 0.35

                dx += (rawX + jX) * shockScale * 9
                dy += (rawY + jY) * shockScale * 5.5
              }
            }

            const a = Math.min(1, p.localT * 1.8) * fadeMult
            if (a < 0.01) return
            ctx.fillStyle = p.colorType === 'cyan'
              ? `rgba(0, 240, 255, ${a})`
              : p.colorType === 'neon'
              ? `rgba(57, 255, 148, ${a})`
              : `rgba(235, 255, 250, ${a})`
            ctx.fillRect(dx, dy, p.size, p.size)
          })
        }

        // ── PHASE 5: LOGO LOCK RETICLE (00:12 - 00:16) ───────────────
        if (elapsed >= T.LOGO_LOCK && elapsed < T.TAGLINE_GLOBE && fadeMult > 0.08) {
          const lockAlpha = clamp((elapsed - T.LOGO_LOCK) / 500, 0, 1) *
            (elapsed > T.TAGLINE_GLOBE - 500 ? (T.TAGLINE_GLOBE - elapsed) / 500 : 1) * fadeMult
          const rot = elapsed * 0.0018
          ctx.save()
          ctx.translate(W / 2, H / 2)

          // Inner cyan ring with notch breaks
          ctx.strokeStyle = `rgba(0, 240, 255, ${0.75 * lockAlpha})`
          ctx.lineWidth = 1.6
          ctx.beginPath()
          ctx.arc(0, 0, Math.min(W, H) * 0.26, rot, rot + Math.PI * 0.7)
          ctx.stroke()
          ctx.beginPath()
          ctx.arc(0, 0, Math.min(W, H) * 0.26, rot + Math.PI, rot + Math.PI * 1.7)
          ctx.stroke()

          // Outer crimson alert targeting arcs
          ctx.strokeStyle = `rgba(255, 59, 92, ${0.7 * lockAlpha})`
          ctx.lineWidth = 2.2
          ctx.beginPath()
          ctx.arc(0, 0, Math.min(W, H) * 0.30, -rot * 0.8, -rot * 0.8 + Math.PI * 0.4)
          ctx.stroke()
          ctx.beginPath()
          ctx.arc(0, 0, Math.min(W, H) * 0.30, -rot * 0.8 + Math.PI, -rot * 0.8 + Math.PI * 1.4)
          ctx.stroke()

          // Target ticks
          ctx.strokeStyle = `rgba(57, 255, 148, ${0.6 * lockAlpha})`
          ctx.lineWidth = 1
          for (let i = 0; i < 4; i++) {
            const ang = (i * Math.PI) / 2
            const r1 = Math.min(W, H) * 0.23
            const r2 = Math.min(W, H) * 0.32
            ctx.beginPath()
            ctx.moveTo(Math.cos(ang) * r1, Math.sin(ang) * r1)
            ctx.lineTo(Math.cos(ang) * r2, Math.sin(ang) * r2)
            ctx.stroke()
          }
          ctx.restore()
        }

        // ── PHASE 6: CYBER GLOBE WIREFRAME (00:16 - 00:20) ───────────
        if (elapsed >= T.TAGLINE_GLOBE && elapsed < T.LIGHT_SHOCK && fadeMult > 0.05) {
          const globeAlpha = clamp((elapsed - T.TAGLINE_GLOBE) / 600, 0, 1) *
            (elapsed > T.LIGHT_SHOCK - 500 ? (T.LIGHT_SHOCK - elapsed) / 500 : 1) * fadeMult
          const globeCenterX = W > 800 ? W * 0.68 : W / 2
          const globeCenterY = H / 2
          const rotY = elapsed * 0.0009
          const rotX = 0.25

          ctx.save()
          ctx.translate(globeCenterX, globeCenterY)

          // Outer glow ring
          const ringGrad = ctx.createRadialGradient(0, 0, globeRadius * 0.8, 0, 0, globeRadius * 1.25)
          ringGrad.addColorStop(0, `rgba(0, 240, 255, ${0.12 * globeAlpha})`)
          ringGrad.addColorStop(0.5, `rgba(57, 255, 148, ${0.08 * globeAlpha})`)
          ringGrad.addColorStop(1, 'rgba(0,0,0,0)')
          ctx.fillStyle = ringGrad
          ctx.beginPath()
          ctx.arc(0, 0, globeRadius * 1.25, 0, Math.PI * 2)
          ctx.fill()

          // Projected 3D dots
          globeDots.forEach((dot) => {
            // Y rotation
            const x1 = dot.x * Math.cos(rotY) + dot.z * Math.sin(rotY)
            const z1 = -dot.x * Math.sin(rotY) + dot.z * Math.cos(rotY)
            // X tilt
            const y2 = dot.y * Math.cos(rotX) - z1 * Math.sin(rotX)
            const z2 = dot.y * Math.sin(rotX) + z1 * Math.cos(rotX)

            // Perspective scale
            const scale = 300 / (300 + z2 * globeRadius * 0.5)
            const px = x1 * globeRadius * scale
            const py = y2 * globeRadius * scale
            const dotAlpha = clamp((z2 + 1) * 0.5, 0.1, 1) * globeAlpha

            ctx.fillStyle = z2 > 0 ? `rgba(0, 240, 255, ${dotAlpha * 0.9})` : `rgba(57, 255, 148, ${dotAlpha * 0.4})`
            ctx.fillRect(px - 1, py - 1, z2 > 0 ? 2.2 : 1.4, z2 > 0 ? 2.2 : 1.4)
          })

          // Orbital rings
          ctx.strokeStyle = `rgba(0, 240, 255, ${0.45 * globeAlpha})`
          ctx.lineWidth = 1.2
          ctx.beginPath()
          ctx.ellipse(0, 0, globeRadius * 1.28, globeRadius * 0.42, -0.35, 0, Math.PI * 2)
          ctx.stroke()
          ctx.restore()
        }

        // ── PHASE 7: VERTICAL LIGHT SHOCK BEAM (00:20 - 00:24) ───────
        if (elapsed >= T.LIGHT_SHOCK && elapsed < T.HOLD_START && fadeMult > 0.05) {
          const beamProg = (elapsed - T.LIGHT_SHOCK) / (T.HOLD_START - T.LIGHT_SHOCK)
          const beamIntensity = (1 - beamProg) * fadeMult
          const beamWidth = clamp(W * 0.045 * (1 + beamProg * 1.5), 14, 80)

          // Intense vertical light column
          const beamGrad = ctx.createLinearGradient(W / 2 - beamWidth, 0, W / 2 + beamWidth, 0)
          beamGrad.addColorStop(0, 'rgba(0, 240, 255, 0)')
          beamGrad.addColorStop(0.3, `rgba(0, 240, 255, ${0.4 * beamIntensity})`)
          beamGrad.addColorStop(0.5, `rgba(255, 255, 255, ${0.85 * beamIntensity})`)
          beamGrad.addColorStop(0.7, `rgba(0, 240, 255, ${0.4 * beamIntensity})`)
          beamGrad.addColorStop(1, 'rgba(0, 240, 255, 0)')
          ctx.fillStyle = beamGrad
          ctx.fillRect(W / 2 - beamWidth, 0, beamWidth * 2, H)

          // Ground light reflection
          const groundSpot = ctx.createRadialGradient(W / 2, H * 0.72, 0, W / 2, H * 0.72, W * 0.35)
          groundSpot.addColorStop(0, `rgba(255, 255, 255, ${0.65 * beamIntensity})`)
          groundSpot.addColorStop(0.3, `rgba(0, 240, 255, ${0.45 * beamIntensity})`)
          groundSpot.addColorStop(1, 'rgba(0, 240, 255, 0)')
          ctx.fillStyle = groundSpot
          ctx.fillRect(0, H * 0.5, W, H * 0.5)
        }

        // ── SHOCKWAVE PULSES ─────────────────────────────────────────
        shockWaves.forEach((wave) => {
          wave.r += wave.spd * (dt / 16) * 4.4
          const wa = Math.max(0, (1 - wave.r / wave.maxR) * 0.85 * fadeMult)
          if (wa <= 0.005) return
          ctx.beginPath()
          ctx.arc(wave.x, wave.y, wave.r, 0, Math.PI * 2)
          ctx.strokeStyle = `rgba(${wave.color}, ${wa})`
          ctx.lineWidth = wave.lw * (1 - wave.r / wave.maxR)
          ctx.stroke()
        })

        // Screen flash overlays
        const flashAlpha = Math.max(
          elapsed >= T.LOGO_LOCK && elapsed < T.LOGO_LOCK + 160 ? (1 - (elapsed - T.LOGO_LOCK) / 160) * 0.45 : 0,
          elapsed >= T.LIGHT_SHOCK && elapsed < T.LIGHT_SHOCK + 260 ? (1 - (elapsed - T.LIGHT_SHOCK) / 260) * 0.75 : 0
        ) * fadeMult
        if (flashAlpha > 0.01) {
          ctx.fillStyle = `rgba(220, 255, 250, ${flashAlpha})`
          ctx.fillRect(-10, -10, W + 20, H + 20)
        }

        // Glitch slice displacements (boot + assembly only, not after stabilization)
        if (elapsed < T.STABILIZE_START && glitch > 0.35 && fadeMult > 0.1) {
          const numSlices = Math.ceil(glitch * 5)
          for (let s = 0; s < numSlices; s++) {
            const sy = Math.floor(Math.random() * H)
            const sh = Math.floor(Math.random() * 12 + 3)
            const sx = Math.round((Math.random() - 0.5) * 42 * glitch)
            if (Math.abs(sx) > 3) {
              try {
                ctx.drawImage(canvas, 0, sy * DPR, W * DPR, sh * DPR, sx, sy, W, sh)
              } catch (_) {}
            }
          }
        }

        ctx.restore()
        animId = requestAnimationFrame(render)
      } // end render

      animId = requestAnimationFrame(render)
    } // end init

    document.fonts.ready.then(init)

    return () => {
      mounted = false
      cancelAnimationFrame(animId)
      removers.forEach((fn) => fn())
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className={`sg-intro${fading ? ' sg-fading' : ''}`} aria-hidden="true">
      <canvas ref={canvasRef} className="sg-canvas" />

      {/* Cyber scanline overlay */}
      <div className="sg-scanlines" />

      {/* Corner HUD brackets */}
      <div className={`sg-corners${showHUD ? ' sg-hud-on' : ''}`}>
        <div className="sg-c sg-tl" /><div className="sg-c sg-tr" />
        <div className="sg-c sg-bl" /><div className="sg-c sg-br" />
      </div>

      {/* Top Header info */}
      <div className="sg-brand">
        <span className="sg-brand-pip" />
        CYBERMIND AI
      </div>

      <div className="sg-phase-wrap">
        <span className="sg-phase-dot" />
        <span className="sg-phase-txt">{activeLog}</span>
      </div>

      {/* Tagline Phase 5: DETECT · ANALYZE · PROTECT */}
      {showDetectTagline && (
        <div className="sg-detect-tagline">
          DETECT &nbsp;&bull;&nbsp; ANALYZE &nbsp;&bull;&nbsp; PROTECT
        </div>
      )}

      {/* Tagline Phase 6: SECURING A SAFER TOMORROW (Storyboard Frame 6) */}
      {showTaglineSecuring && (
        <div className="sg-securing-panel">
          <div className="sg-securing-line1">SECURING</div>
          <div className="sg-securing-line2">A SAFER</div>
          <div className="sg-securing-line3">TOMORROW</div>
        </div>
      )}

      {/* SYSTEM ONLINE Badge Phase 7/8/9 */}
      {showSystemOnline && (
        <div className="sg-online-badge">
          <span className="sg-online-pip" />
          SYSTEM ONLINE
        </div>
      )}

      {/* Bottom Progress Bar */}
      <div className="sg-progress">
        <div className="sg-progress-fill" style={{ width: `${progress}%` }} />
      </div>

      {/* Skip Button */}
      <button className="sg-skip" onClick={doSkip} type="button">
        SKIP &nbsp;↗
      </button>
    </div>
  )
}
