import { useEffect, useRef } from 'react'
import * as THREE from 'three'

/**
 * SessionOrbit — live 3D "session constellation" for the dashboard hero.
 *   sessions   active session count   → orbiting satellites
 *   locked     frozen session count   → red satellites inside a rotating cage
 *   threat     SAFE | SUSPICIOUS | LOCKDOWN → core colour, speed
 *   pulse      bump on every live event → shockwave ring + core flash
 * Drag to rotate, hover to slow down.
 */
const COL = {
  SAFE: [new THREE.Color('#8f8bff'), new THREE.Color('#5ee1ff')],
  SUSPICIOUS: [new THREE.Color('#ffb547'), new THREE.Color('#ff7a3d')],
  LOCKDOWN: [new THREE.Color('#ff4d73'), new THREE.Color('#ff9a3d')],
}

export default function SessionOrbit({ sessions = 0, locked = 0, threat = 'SAFE', pulse = 0 }) {
  const mountRef = useRef(null)
  const api = useRef({})

  useEffect(() => { api.current.setSessions?.(sessions, locked) }, [sessions, locked])
  useEffect(() => { api.current.setThreat?.(threat) }, [threat])
  useEffect(() => { if (pulse) api.current.pulse?.() }, [pulse])

  useEffect(() => {
    const mount = mountRef.current
    let renderer
    try { renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true }) } catch { return }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setSize(mount.clientWidth, mount.clientHeight)
    renderer.setClearColor(0x000000, 0)
    mount.appendChild(renderer.domElement)

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(42, mount.clientWidth / mount.clientHeight, 0.1, 100)
    camera.position.set(0, 3.2, 15)
    camera.lookAt(0, 0, 0)

    const root = new THREE.Group(); scene.add(root)
    const accent = COL.SAFE[0].clone(), accent2 = COL.SAFE[1].clone()
    let target = 'SAFE'

    // ---- core ----
    const coreMat = new THREE.MeshBasicMaterial({ color: accent, wireframe: true, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending })
    const core = new THREE.Mesh(new THREE.IcosahedronGeometry(1.5, 2), coreMat)
    const coreSolid = new THREE.Mesh(new THREE.IcosahedronGeometry(1.15, 1), new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.35, blending: THREE.AdditiveBlending }))
    const halo = new THREE.Sprite(new THREE.SpriteMaterial({
      map: (() => { const c = document.createElement('canvas'); c.width = c.height = 128; const g = c.getContext('2d'); const gr = g.createRadialGradient(64, 64, 0, 64, 64, 64); gr.addColorStop(0, 'rgba(255,255,255,.9)'); gr.addColorStop(0.3, 'rgba(255,255,255,.25)'); gr.addColorStop(1, 'rgba(255,255,255,0)'); g.fillStyle = gr; g.fillRect(0, 0, 128, 128); return new THREE.CanvasTexture(c) })(),
      color: accent, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, opacity: 0.7,
    }))
    halo.scale.set(9, 9, 1)
    root.add(core, coreSolid, halo)

    // ---- orbit rings ----
    const ringDefs = [{ r: 3.6, tilt: [0.5, 0, 0.2] }, { r: 5.2, tilt: [-0.35, 0.6, 0] }, { r: 6.9, tilt: [0.15, -0.5, 0.4] }]
    const ringMat = new THREE.LineBasicMaterial({ color: accent, transparent: true, opacity: 0.28, blending: THREE.AdditiveBlending })
    const ringGroups = ringDefs.map((d) => {
      const pts = []; for (let i = 0; i <= 160; i++) { const a = (i / 160) * Math.PI * 2; pts.push(new THREE.Vector3(Math.cos(a) * d.r, 0, Math.sin(a) * d.r)) }
      const g = new THREE.Group(); g.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), ringMat)); g.rotation.set(...d.tilt); root.add(g)
      return { g, d, sats: [] }
    })

    // ---- satellites (sessions) ----
    const satGeo = new THREE.SphereGeometry(0.13, 12, 12)
    const cageGeo = new THREE.OctahedronGeometry(0.42, 0)
    const satMat = new THREE.MeshBasicMaterial({ color: 0xffffff })
    const lockMat = new THREE.MeshBasicMaterial({ color: 0xff4d73 })
    const cageMat = new THREE.MeshBasicMaterial({ color: 0xff4d73, wireframe: true, transparent: true, opacity: 0.9 })
    const trailMat = new THREE.LineBasicMaterial({ color: accent2, transparent: true, opacity: 0.35, blending: THREE.AdditiveBlending })
    let sats = []
    const clearSats = () => { sats.forEach((s) => { s.ring.g.remove(s.pivot) }); sats = [] }
    const build = (count, lockedCount) => {
      clearSats()
      const total = Math.min(count, 42)
      const nLocked = Math.min(lockedCount, total)
      for (let i = 0; i < total; i++) {
        const ring = ringGroups[i % 3]
        const pivot = new THREE.Group()
        const isLocked = i < nLocked
        const m = new THREE.Mesh(satGeo, isLocked ? lockMat : satMat.clone())
        if (!isLocked) m.material.color.copy(Math.random() < 0.5 ? accent : accent2)
        m.scale.setScalar(isLocked ? 1.5 : 0.8 + Math.random() * 0.7)
        pivot.add(m)
        let cage = null
        if (isLocked) { cage = new THREE.Mesh(cageGeo, cageMat); pivot.add(cage) }
        // short motion trail
        const tp = []; for (let k = 0; k < 14; k++) tp.push(new THREE.Vector3(Math.cos(-k * 0.045) * ring.d.r, 0, Math.sin(-k * 0.045) * ring.d.r))
        const trail = new THREE.Line(new THREE.BufferGeometry().setFromPoints(tp), trailMat); trail.visible = false
        ring.g.add(pivot)
        sats.push({ pivot, ring, mesh: m, cage, a: Math.random() * Math.PI * 2, sp: (0.25 + Math.random() * 0.35) * (ring.d.r > 5 ? 0.7 : 1) * (Math.random() < 0.5 ? 1 : -1), locked: isLocked })
      }
    }
    build(sessions, locked)

    // ---- shockwave rings ----
    const waves = []
    const addWave = () => {
      const m = new THREE.Mesh(new THREE.RingGeometry(0.97, 1, 96), new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.8, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }))
      m.rotation.x = Math.PI / 2 + 0.3; root.add(m); waves.push({ m, born: performance.now() })
    }

    // ---- dust ----
    const dp = new Float32Array(260 * 3)
    for (let i = 0; i < 260; i++) { const r = 5 + Math.random() * 9, th = Math.random() * 6.28, ph = Math.acos(Math.random() * 2 - 1); dp.set([r * Math.sin(ph) * Math.cos(th), r * Math.cos(ph) * 0.7, r * Math.sin(ph) * Math.sin(th)], i * 3) }
    const dg = new THREE.BufferGeometry(); dg.setAttribute('position', new THREE.BufferAttribute(dp, 3))
    const dust = new THREE.Points(dg, new THREE.PointsMaterial({ color: 0x8f8bff, size: 0.05, transparent: true, opacity: 0.6, blending: THREE.AdditiveBlending, depthWrite: false }))
    root.add(dust)

    // ---- interaction ----
    let dragging = false, lx = 0, ly = 0, vx = 0, vy = 0, hover = false, flash = 0
    const down = (e) => { dragging = true; lx = e.clientX; ly = e.clientY; mount.setPointerCapture?.(e.pointerId) }
    const move = (e) => { if (!dragging) return; vx = (e.clientX - lx) * 0.005; vy = (e.clientY - ly) * 0.005; root.rotation.y += vx; root.rotation.x = Math.max(-0.9, Math.min(0.9, root.rotation.x + vy)); lx = e.clientX; ly = e.clientY }
    const up = () => { dragging = false }
    const enter = () => { hover = true }, leave = () => { hover = false; dragging = false }
    mount.addEventListener('pointerdown', down); window.addEventListener('pointermove', move); window.addEventListener('pointerup', up)
    mount.addEventListener('pointerenter', enter); mount.addEventListener('pointerleave', leave)

    api.current = {
      setSessions: (c, l) => build(c, l),
      setThreat: (t) => { target = t },
      pulse: () => { addWave(); flash = 1 },
    }

    const onResize = () => { renderer.setSize(mount.clientWidth, mount.clientHeight); camera.aspect = mount.clientWidth / mount.clientHeight; camera.updateProjectionMatrix() }
    window.addEventListener('resize', onResize)

    let raf = 0, last = performance.now(), t = 0, running = true
    const onVis = () => { running = !document.hidden; last = performance.now() }
    document.addEventListener('visibilitychange', onVis)
    const tick = (now) => {
      raf = requestAnimationFrame(tick)
      if (!running) return
      const dt = Math.min((now - last) / 1000, 0.05); last = now
      const speed = (hover ? 0.35 : 1) * (target === 'LOCKDOWN' ? 1.8 : target === 'SUSPICIOUS' ? 1.25 : 1)
      t += dt * speed
      accent.lerp(COL[target][0], 1 - Math.pow(0.04, dt)); accent2.lerp(COL[target][1], 1 - Math.pow(0.04, dt))
      coreMat.color.copy(accent); coreSolid.material.color.copy(accent); halo.material.color.copy(accent); ringMat.color.copy(accent); trailMat.color.copy(accent2)
      flash = Math.max(0, flash - dt * 2.2)
      core.rotation.y = t * 0.5; core.rotation.x = t * 0.25
      coreSolid.rotation.y = -t * 0.7
      const pul = 1 + 0.06 * Math.sin(t * 3) + flash * 0.25
      core.scale.setScalar(pul); coreSolid.scale.setScalar(pul * (target === 'LOCKDOWN' ? 1 + 0.12 * Math.sin(t * 14) : 1))
      halo.material.opacity = 0.55 + flash * 0.4
      if (!dragging) { root.rotation.y += dt * 0.12 * speed + vx * 0.9; vx *= 0.94; root.rotation.x += (0.18 - root.rotation.x) * 0.02 }
      ringGroups.forEach((r, i) => { r.g.rotation.y += dt * 0.04 * (i + 1) * speed })
      sats.forEach((s) => {
        s.a += dt * s.sp * speed
        s.pivot.position.set(Math.cos(s.a) * s.ring.d.r, 0, Math.sin(s.a) * s.ring.d.r)
        if (s.cage) { s.cage.rotation.x += dt * 3; s.cage.rotation.y += dt * 2; s.cage.scale.setScalar(1 + 0.15 * Math.sin(t * 8)) }
      })
      for (let i = waves.length - 1; i >= 0; i--) {
        const k = (now - waves[i].born) / 1400
        if (k >= 1) { root.remove(waves[i].m); waves[i].m.geometry.dispose(); waves[i].m.material.dispose(); waves.splice(i, 1); continue }
        waves[i].m.scale.setScalar(1.5 + k * 9); waves[i].m.material.opacity = (1 - k) * 0.7; waves[i].m.material.color.copy(accent)
      }
      renderer.render(scene, camera)
    }
    raf = requestAnimationFrame(tick)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', onResize); window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up)
      document.removeEventListener('visibilitychange', onVis)
      mount.removeEventListener('pointerdown', down); mount.removeEventListener('pointerenter', enter); mount.removeEventListener('pointerleave', leave)
      renderer.dispose(); scene.traverse((o) => { o.geometry?.dispose?.(); o.material?.dispose?.() })
      if (renderer.domElement.parentNode === mount) mount.removeChild(renderer.domElement)
      api.current = {}
    }
  }, [])

  return (
    <div className="cm-orbit">
      <div className="cm-orbit-canvas" ref={mountRef} />
      <div className="cm-orbit-label mono">LIVE SESSION CONSTELLATION</div>
      <div className="cm-orbit-legend mono"><span><i className="a" />session</span><span><i className="r" />locked</span><span className="hint">drag to rotate</span></div>
    </div>
  )
}
