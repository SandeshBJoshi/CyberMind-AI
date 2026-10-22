/**
 * ParticleBackground — Subtle global constellation canvas
 * Fixed, full-screen, behind all UI. Particles drift, connect with thin
 * lines when nearby, and gently react to cursor movement.
 * Pauses when tab hidden. Respects prefers-reduced-motion.
 */
import { useEffect, useRef } from 'react'

const PARTICLE_COUNT_BASE = 55   // Scales with window area
const CONNECTION_DIST = 130      // px threshold for drawing edges
const MOUSE_REPEL_DIST = 90      // px — cursor nudges nearby particles
const SPEED_BASE = 0.22
const EDGE_ALPHA_MAX = 0.18      // Keep lines subtle

export default function ParticleBackground() {
  const canvasRef = useRef(null)

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return

    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    let width, height, dpr
    let particles = []
    let animId
    let mouse = { x: -9999, y: -9999 }
    let hidden = false

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2)
      width = window.innerWidth
      height = window.innerHeight
      canvas.width = width * dpr
      canvas.height = height * dpr
      canvas.style.width = width + 'px'
      canvas.style.height = height + 'px'
      ctx.scale(dpr, dpr)
      init()
    }

    const init = () => {
      const area = width * height
      const count = Math.min(Math.round(area / 22000) + PARTICLE_COUNT_BASE, 110)
      particles = Array.from({ length: count }, () => makeParticle())
    }

    const makeParticle = () => ({
      x: Math.random() * (width || window.innerWidth),
      y: Math.random() * (height || window.innerHeight),
      vx: (Math.random() - 0.5) * SPEED_BASE * 2,
      vy: (Math.random() - 0.5) * SPEED_BASE * 2,
      r: Math.random() * 1.6 + 0.6,
      // Subtle green/cyan split
      hue: Math.random() < 0.7 ? 150 : 185,
      opacity: Math.random() * 0.4 + 0.15,
    })

    const draw = () => {
      if (hidden) {
        animId = requestAnimationFrame(draw)
        return
      }

      ctx.clearRect(0, 0, width, height)

      // Update and draw particles
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i]

        // Mouse repel
        const dx = p.x - mouse.x
        const dy = p.y - mouse.y
        const dist = Math.sqrt(dx * dx + dy * dy)
        if (dist < MOUSE_REPEL_DIST && dist > 0) {
          const force = (MOUSE_REPEL_DIST - dist) / MOUSE_REPEL_DIST * 0.5
          p.vx += (dx / dist) * force * 0.08
          p.vy += (dy / dist) * force * 0.08
        }

        // Velocity damping
        p.vx *= 0.995
        p.vy *= 0.995

        // Clamp speed
        const speed = Math.sqrt(p.vx * p.vx + p.vy * p.vy)
        const maxSpeed = SPEED_BASE * 2.5
        if (speed > maxSpeed) {
          p.vx = (p.vx / speed) * maxSpeed
          p.vy = (p.vy / speed) * maxSpeed
        }

        // Drift nudge so particles don't stop entirely
        if (speed < 0.05) {
          p.vx += (Math.random() - 0.5) * 0.04
          p.vy += (Math.random() - 0.5) * 0.04
        }

        p.x += p.vx
        p.y += p.vy

        // Wrap edges
        if (p.x < -10) p.x = width + 10
        if (p.x > width + 10) p.x = -10
        if (p.y < -10) p.y = height + 10
        if (p.y > height + 10) p.y = -10

        // Draw dot
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fillStyle = `hsla(${p.hue}, 100%, 65%, ${p.opacity})`
        ctx.fill()

        // Draw connections
        for (let j = i + 1; j < particles.length; j++) {
          const q = particles[j]
          const ex = p.x - q.x
          const ey = p.y - q.y
          const edgeDist = Math.sqrt(ex * ex + ey * ey)
          if (edgeDist < CONNECTION_DIST) {
            const alpha = EDGE_ALPHA_MAX * (1 - edgeDist / CONNECTION_DIST)
            ctx.beginPath()
            ctx.moveTo(p.x, p.y)
            ctx.lineTo(q.x, q.y)
            ctx.strokeStyle = `hsla(${(p.hue + q.hue) / 2}, 80%, 65%, ${alpha})`
            ctx.lineWidth = 0.6
            ctx.stroke()
          }
        }
      }

      animId = requestAnimationFrame(draw)
    }

    const onMouseMove = (e) => {
      mouse.x = e.clientX
      mouse.y = e.clientY
    }
    const onVisChange = () => { hidden = document.hidden }

    window.addEventListener('resize', resize)
    window.addEventListener('mousemove', onMouseMove)
    document.addEventListener('visibilitychange', onVisChange)

    resize()
    draw()

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('visibilitychange', onVisChange)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        inset: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: 0,
        opacity: 0.55,
      }}
      aria-hidden="true"
    />
  )
}
