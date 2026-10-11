import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js'
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js'
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js'
import { OutputPass } from 'three/examples/jsm/postprocessing/OutputPass.js'

/**
 * ThreatField — a living neural sphere that mirrors the security posture.
 *   threat: 'SAFE' | 'SUSPICIOUS' | 'LOCKDOWN'  → colour, rotation speed, jitter
 *   pulse:  number, increment it on every security event → ripple across the sphere
 *   mode:   'hero' (sphere shifted right, bright) | 'ambient' (dimmer, centred)
 */
const COLORS = {
  SAFE: new THREE.Color('#8f8bff'),
  SUSPICIOUS: new THREE.Color('#ffb547'),
  LOCKDOWN: new THREE.Color('#ff4d73'),
}
const ACCENT2 = {
  SAFE: new THREE.Color('#4fe3ff'),
  SUSPICIOUS: new THREE.Color('#ff7a3d'),
  LOCKDOWN: new THREE.Color('#ff9a3d'),
}

// Scroll journey: one camera pose per station. Scrolling flies the camera from outside the network,
// through its shell, into the core — then out the far side.
const POSES = [
  { p: [0, 0, 19], l: [0, 0, 0] },          // 0 dashboard        OUTSIDE
  { p: [-10, 3.5, 12], l: [0, 0, 0] },      // 1 attacker         ORBIT
  { p: [4, 1, 8.2], l: [0, 0, 0] },         // 2 email analysis   SHELL
  { p: [-5, 1.6, 7], l: [0, 0, -2] },       // 3 sessions         MEMBRANE
  { p: [0, 0, 5.6], l: [0, 0, -4] },        // 4 attacker         INSIDE
  { p: [0, 0.2, 0.4], l: [0, 0, -5] },      // 5 integrations     CORE
  { p: [7, 2.5, -15], l: [0, 0, 0] },       // 6 assistant        EXIT (looking back at the network)
]

const COMMON = /* glsl */`
  uniform float uTime, uPulseT, uAlert, uDim;
  uniform vec3 uPulseDir, uColA, uColB;
  float hash(vec3 p){ return fract(sin(dot(p, vec3(12.9898,78.233,37.719))) * 43758.5453); }
  vec3 jitter(vec3 p){
    float s = hash(p);
    float a = uAlert * (.05 + .12 * sin(uTime * 14. + s * 40.));
    return p * (1. + a) + uAlert * .06 * vec3(sin(uTime*23.+s*50.), cos(uTime*19.+s*30.), sin(uTime*17.+s*10.));
  }
  float wave(vec3 p){
    float ang = acos(clamp(dot(normalize(p), uPulseDir), -1., 1.));
    float r = uPulseT * 2.6;
    return exp(-pow((ang - r) / .22, 2.)) * exp(-uPulseT * .9);
  }
`

function fib(n, r) {
  const out = new Float32Array(n * 3)
  for (let i = 0; i < n; i++) {
    const k = i + 0.5
    const phi = Math.acos(1 - (2 * k) / n)
    const th = Math.PI * (1 + Math.sqrt(5)) * k
    const rr = r * (0.985 + Math.random() * 0.03)
    out.set([rr * Math.cos(th) * Math.sin(phi), rr * Math.sin(th) * Math.sin(phi), rr * Math.cos(phi)], i * 3)
  }
  return out
}

export default function ThreatField({ threat = 'SAFE', pulse = 0, mode = 'hero', journey = null, visible = true }) {
  const mountRef = useRef(null)
  const apiRef = useRef({})

  // push prop changes into the running scene without re-creating it
  useEffect(() => { apiRef.current.setThreat?.(threat) }, [threat])
  useEffect(() => { if (pulse) apiRef.current.firePulse?.() }, [pulse])
  useEffect(() => { apiRef.current.setMode?.(mode) }, [mode])
  useEffect(() => { apiRef.current.setVisible?.(visible) }, [visible])

  useEffect(() => {
    const mount = mountRef.current
    let renderer
    try {
      renderer = new THREE.WebGLRenderer({ antialias: false, alpha: true, powerPreference: 'high-performance' })
    } catch {
      return // no WebGL — the CSS background still looks fine
    }
    const small = window.innerWidth < 760
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, small ? 1.25 : 1.6))
    renderer.setSize(mount.clientWidth, mount.clientHeight)
    renderer.toneMapping = THREE.ACESFilmicToneMapping
    renderer.setClearColor(0x000000, 0)
    mount.appendChild(renderer.domElement)

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(50, mount.clientWidth / mount.clientHeight, 0.1, 200)
    camera.position.set(0, 0, 19)

    const uniforms = {
      uTime: { value: 0 }, uPulseT: { value: 99 }, uAlert: { value: 0 }, uDim: { value: 1 },
      uPulseDir: { value: new THREE.Vector3(0, 1, 0) },
      uColA: { value: COLORS.SAFE.clone() }, uColB: { value: ACCENT2.SAFE.clone() },
    }

    // ---- node shells ----
    const N1 = small ? 520 : 1100, N2 = small ? 160 : 340
    const outer = fib(N1, 7), inner = fib(N2, 4.3)
    const pos = new Float32Array((N1 + N2) * 3)
    pos.set(outer, 0); pos.set(inner, N1 * 3)
    const N = N1 + N2
    const sz = new Float32Array(N), mixv = new Float32Array(N)
    for (let i = 0; i < N; i++) { sz[i] = Math.random() < 0.05 ? 3 + Math.random() * 2 : 0.8 + Math.random() * 1.2; mixv[i] = Math.random() }

    const pg = new THREE.BufferGeometry()
    pg.setAttribute('position', new THREE.BufferAttribute(pos, 3))
    pg.setAttribute('aSize', new THREE.BufferAttribute(sz, 1))
    pg.setAttribute('aMix', new THREE.BufferAttribute(mixv, 1))
    const pointMat = new THREE.ShaderMaterial({
      uniforms: { ...uniforms, uPx: { value: renderer.getPixelRatio() } },
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
      vertexShader: `${COMMON}
        uniform float uPx; attribute float aSize, aMix; varying vec3 vCol; varying float vB;
        void main(){
          vec3 p = jitter(position);
          vec4 mv = modelViewMatrix * vec4(p, 1.);
          gl_Position = projectionMatrix * mv;
          float w = wave(position);
          gl_PointSize = min((aSize + w * 5.) * uPx * (30. / -mv.z), 40.);
          vCol = mix(uColA, uColB, aMix * .6 + w);
          vB = (.55 + .45 * sin(uTime * 1.6 + hash(position) * 50.) + w * 3.) * uDim;
        }`,
      fragmentShader: `varying vec3 vCol; varying float vB;
        void main(){ float d = length(gl_PointCoord - .5); if (d > .5) discard;
          float g = pow(1. - d * 2., 2.); gl_FragColor = vec4(vCol * (g * 1.2 + smoothstep(.15, 0., d)) * vB, 1.); }`,
    })
    const group = new THREE.Group()
    group.add(new THREE.Points(pg, pointMat))

    // ---- synapses: 2 nearest neighbours per node, same-shell only ----
    const edges = new Set()
    const nearest = (from, to) => {
      for (let i = from; i < to; i++) {
        let b1 = -1, b2 = -1, d1 = 1e9, d2 = 1e9
        const x = pos[i * 3], y = pos[i * 3 + 1], z = pos[i * 3 + 2]
        for (let j = from; j < to; j++) {
          if (j === i) continue
          const dx = pos[j * 3] - x, dy = pos[j * 3 + 1] - y, dz = pos[j * 3 + 2] - z
          const d = dx * dx + dy * dy + dz * dz
          if (d < d1) { d2 = d1; b2 = b1; d1 = d; b1 = j } else if (d < d2) { d2 = d; b2 = j }
        }
        for (const j of [b1, b2]) if (j >= 0) edges.add(i < j ? i * N + j : j * N + i)
      }
    }
    nearest(0, N1); nearest(N1, N)
    // a few long "cross-shell" links so the structure feels connected
    for (let k = 0; k < (small ? 40 : 110); k++) edges.add(Math.floor(Math.random() * N1) * N + (N1 + Math.floor(Math.random() * N2)))
    const list = [...edges]
    const lp = new Float32Array(list.length * 6), lt = new Float32Array(list.length * 2), ls = new Float32Array(list.length * 2)
    list.forEach((key, e) => {
      const i = Math.floor(key / N), j = key % N, s = Math.random()
      lp.set(pos.subarray(i * 3, i * 3 + 3), e * 6); lp.set(pos.subarray(j * 3, j * 3 + 3), e * 6 + 3)
      lt[e * 2] = 0; lt[e * 2 + 1] = 1; ls[e * 2] = s; ls[e * 2 + 1] = s
    })
    const lg = new THREE.BufferGeometry()
    lg.setAttribute('position', new THREE.BufferAttribute(lp, 3))
    lg.setAttribute('aT', new THREE.BufferAttribute(lt, 1))
    lg.setAttribute('aS', new THREE.BufferAttribute(ls, 1))
    const lineMat = new THREE.ShaderMaterial({
      uniforms, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
      vertexShader: `${COMMON}
        attribute float aT, aS; varying vec3 vCol; varying float vT, vS, vW;
        void main(){ vec3 p = jitter(position); gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.);
          vW = wave(position); vCol = mix(uColA, uColB, aS * .5 + vW); vT = aT; vS = aS; }`,
      fragmentShader: `uniform float uTime, uDim; varying vec3 vCol; varying float vT, vS, vW;
        void main(){ float x = fract(uTime * .22 + vS * 9.); float pulse = smoothstep(.12, 0., abs(vT - x));
          gl_FragColor = vec4(vCol * (.08 + pulse * 1.5 + vW * 2.2) * uDim, 1.); }`,
    })
    group.add(new THREE.LineSegments(lg, lineMat))

    // ---- orbit rings ----
    const ringMat = new THREE.LineBasicMaterial({ color: 0x8f8bff, transparent: true, opacity: 0.18, blending: THREE.AdditiveBlending })
    const rings = []
    for (let r = 0; r < 3; r++) {
      const pts = []
      for (let a = 0; a <= 128; a++) { const t = (a / 128) * Math.PI * 2; pts.push(new THREE.Vector3(Math.cos(t) * (9 + r * 1.1), 0, Math.sin(t) * (9 + r * 1.1))) }
      const ring = new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), ringMat)
      ring.rotation.set(0.9 + r * 0.7, r * 1.1, r * 0.5)
      rings.push(ring); group.add(ring)
    }
    scene.add(group)

    // ---- perspective grid floor (depth cue) ----
    const grid = new THREE.GridHelper(140, 56, 0xffffff, 0xffffff)
    grid.material.transparent = true; grid.material.opacity = 0.13; grid.material.depthWrite = false
    grid.material.blending = THREE.AdditiveBlending
    grid.position.y = -10.5
    scene.add(grid)

    // ---- inflow: telemetry streams spiralling into the core ----
    const IN = small ? 90 : 240
    const inPos = new Float32Array(IN * 3), inDir = [], inR = new Float32Array(IN), inSp = new Float32Array(IN)
    for (let i = 0; i < IN; i++) {
      const th = Math.random() * 6.283, ph = Math.acos(Math.random() * 2 - 1)
      inDir.push(new THREE.Vector3(Math.sin(ph) * Math.cos(th), Math.sin(ph) * Math.sin(th), Math.cos(ph)))
      inR[i] = 8 + Math.random() * 14; inSp[i] = 1.5 + Math.random() * 2.5
    }
    const inGeo = new THREE.BufferGeometry(); inGeo.setAttribute('position', new THREE.BufferAttribute(inPos, 3))
    const inMat = new THREE.PointsMaterial({ color: 0x8f8bff, size: 0.14, transparent: true, opacity: 0.85, depthWrite: false, blending: THREE.AdditiveBlending })
    group.add(new THREE.Points(inGeo, inMat))

    // ---- satellites: sessions orbiting the core ----
    const sats = []
    const satGeo = new THREE.OctahedronGeometry(0.22, 0)
    const satMat = new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending })
    for (let i = 0; i < (small ? 8 : 20); i++) {
      const m = new THREE.Mesh(satGeo, satMat)
      sats.push({ m, r: 10 + Math.random() * 4, a: Math.random() * 6.283, sp: (0.08 + Math.random() * 0.15) * (Math.random() < 0.5 ? 1 : -1), inc: (Math.random() - 0.5) * 1.4, ph: Math.random() * 6.283 })
      group.add(m)
    }

    // ---- the core (heart of the network) ----
    const coreMat = new THREE.MeshBasicMaterial({ color: 0x8f8bff, wireframe: true, transparent: true, opacity: 0.6, blending: THREE.AdditiveBlending })
    const coreMesh = new THREE.Mesh(new THREE.IcosahedronGeometry(1.0, 2), coreMat)
    const coreFill = new THREE.Mesh(new THREE.IcosahedronGeometry(0.62, 1), new THREE.MeshBasicMaterial({ color: 0x5ee1ff, transparent: true, opacity: 0.22, blending: THREE.AdditiveBlending, depthWrite: false }))
    group.add(coreMesh, coreFill)

    // ---- dust ----
    const DN = small ? 300 : 900, dp = new Float32Array(DN * 3)
    for (let i = 0; i < DN; i++) dp.set([(Math.random() - 0.5) * 90, (Math.random() - 0.5) * 60, (Math.random() - 0.5) * 60 - 8], i * 3)
    const dg = new THREE.BufferGeometry(); dg.setAttribute('position', new THREE.BufferAttribute(dp, 3))
    const dust = new THREE.Points(dg, new THREE.PointsMaterial({ color: 0x6f7bff, size: 0.09, transparent: true, opacity: 0.45, depthWrite: false, blending: THREE.AdditiveBlending }))
    scene.add(dust)

    // ---- warp streaks (live in camera space, only visible during a flight) ----
    const WS = small ? 220 : 480
    const wp = new Float32Array(WS * 6), wSeed = new Float32Array(WS * 2), wT = new Float32Array(WS * 2)
    for (let i = 0; i < WS; i++) {
      const a = Math.random() * 6.283, r = 1.4 + Math.pow(Math.random(), 0.8) * 11, z = Math.random() * 80, sd = Math.random()
      const x = Math.cos(a) * r, y = Math.sin(a) * r
      wp.set([x, y, z, x, y, z], i * 6); wSeed[i * 2] = sd; wSeed[i * 2 + 1] = sd; wT[i * 2] = 0; wT[i * 2 + 1] = 1
    }
    const wg = new THREE.BufferGeometry()
    wg.setAttribute('position', new THREE.BufferAttribute(wp, 3)); wg.setAttribute('aP', new THREE.BufferAttribute(wp, 3))
    wg.setAttribute('aSeed', new THREE.BufferAttribute(wSeed, 1)); wg.setAttribute('aT', new THREE.BufferAttribute(wT, 1))
    const warpU = { uTime: uniforms.uTime, uWarp: { value: 0 }, uColA: uniforms.uColA, uColB: uniforms.uColB }
    const warpLines = new THREE.LineSegments(wg, new THREE.ShaderMaterial({
      uniforms: warpU, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
      vertexShader: `uniform float uTime, uWarp; uniform vec3 uColA, uColB; attribute vec3 aP; attribute float aSeed, aT; varying vec3 vCol; varying float vA;
        void main(){
          float z = mod(aP.z + uTime * 70. * (.5 + aSeed), 80.) - 80.;
          vec3 p = vec3(aP.xy, z - aT * uWarp * 16. * (.4 + aSeed));
          gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.);
          vA = uWarp * smoothstep(-80., -45., z) * smoothstep(0., -6., z) * (1. - aT * .8);
          vCol = mix(uColA, uColB, aSeed);
        }`,
      fragmentShader: `varying vec3 vCol; varying float vA; void main(){ gl_FragColor = vec4(vCol * vA * 0.55, 1.); }`,
    }))
    warpLines.frustumCulled = false
    camera.add(warpLines); scene.add(camera)

    // ---- post ----
    const composer = new EffectComposer(renderer)
    composer.addPass(new RenderPass(scene, camera))
    const bloom = new UnrealBloomPass(new THREE.Vector2(mount.clientWidth, mount.clientHeight), 0.9, 0.6, 0.05)
    composer.addPass(bloom); composer.addPass(new OutputPass())

    // ---- state ----
    let tThreat = 'SAFE', alertTarget = 0, modeNow = mode
    let targetX = 0, targetDim = 1, curX = 0
    let px = 0, py = 0, running = true, raf = 0, last = performance.now(), time = 0
    const colA = COLORS.SAFE.clone(), colB = ACCENT2.SAFE.clone()
    // camera director state
    let visibleNow = visible
    const tmpP = new THREE.Vector3(), tmpL = new THREE.Vector3(), tmpV = new THREE.Vector3()
    let jIdx = journey?.current?.idx || 0, spx = 0, spy = 0

    const layout = () => {
      const aspect = mount.clientWidth / mount.clientHeight
      targetX = modeNow === 'hero' && aspect > 1.15 ? 6.4 : 0
      targetDim = modeNow === 'hero' ? 1 : 0.5
      satMat.opacity = modeNow === 'hero' ? 0.9 : 0.32
      inMat.opacity = modeNow === 'hero' ? 0.85 : 0.45
    }
    apiRef.current = {
      setThreat: (t) => { tThreat = t; alertTarget = t === 'LOCKDOWN' ? 1 : t === 'SUSPICIOUS' ? 0.18 : 0 },
      firePulse: () => {
        uniforms.uPulseDir.value.set(Math.random() - 0.5, Math.random() - 0.5, Math.random() - 0.5).normalize()
        uniforms.uPulseT.value = 0
      },
      setMode: (m) => { modeNow = m; layout() },
      setVisible: (v) => { visibleNow = v },
    }
    layout()
    apiRef.current.setThreat(threat)

    const onMove = (e) => { px = e.clientX / window.innerWidth - 0.5; py = e.clientY / window.innerHeight - 0.5 }
    const onResize = () => {
      const w = mount.clientWidth, h = mount.clientHeight
      renderer.setSize(w, h); composer.setSize(w, h)
      camera.aspect = w / h; camera.updateProjectionMatrix(); layout()
    }
    const onVis = () => { running = !document.hidden; last = performance.now() }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('resize', onResize)
    document.addEventListener('visibilitychange', onVis)

    const tick = (now) => {
      raf = requestAnimationFrame(tick)
      if (!running) return
      const dt = Math.min((now - last) / 1000, 0.05); last = now
      const speed = 1 + uniforms.uAlert.value * 2.5
      time += dt * speed
      uniforms.uTime.value = time
      uniforms.uPulseT.value += dt
      uniforms.uAlert.value += (alertTarget - uniforms.uAlert.value) * (1 - Math.pow(0.02, dt))
      uniforms.uDim.value += (targetDim * (journey?.current?.open ? 0.62 : 1) - uniforms.uDim.value) * (1 - Math.pow(0.05, dt))
      colA.lerp(COLORS[tThreat], 1 - Math.pow(0.04, dt)); colB.lerp(ACCENT2[tThreat], 1 - Math.pow(0.04, dt))
      uniforms.uColA.value.copy(colA); uniforms.uColB.value.copy(colB)
      ringMat.color.copy(colA)

      curX += (targetX - curX) * (1 - Math.pow(0.03, dt))
      group.position.x = curX
      group.rotation.y += dt * 0.07 * speed
      group.rotation.x += ((py * 0.5) - group.rotation.x) * 0.03
      group.rotation.z = Math.sin(time * 0.2) * 0.06
      rings.forEach((r, i) => { r.rotation.y += dt * (0.05 + i * 0.03) * speed })
      // ---- camera director: scroll progress flies the camera through the network ----
      spx += (px - spx) * 0.05; spy += (py - spy) * 0.05
      let warpAmt = 0, roll = 0, shell = 0
      if (modeNow === 'hero' || !journey) {
        tmpP.set(0, 0, 19); tmpL.set(curX * 0.35, 0, 0)
      } else {
        const tgt = journey.current.idx
        const diff = tgt - jIdx
        jIdx += diff * (1 - Math.pow(0.0009, dt))
        const f = Math.min(POSES.length - 1, Math.max(0, jIdx))
        const i = Math.min(POSES.length - 2, Math.floor(f)), u = f - i
        const e = u + (u * u * (3 - 2 * u) - u) * 0.6
        tmpP.set(...POSES[i].p).lerp(tmpV.set(...POSES[i + 1].p), e)
        tmpL.set(...POSES[i].l).lerp(tmpV.set(...POSES[i + 1].l), e)
        warpAmt = Math.min(0.85, Math.abs(diff) * 0.8)
        roll = Math.max(-1, Math.min(1, diff)) * 0.14 * warpAmt
        const r = tmpP.length() // flash as the camera crosses the outer / inner shell
        shell = Math.exp(-Math.pow((r - 7) / 0.9, 2)) + Math.exp(-Math.pow((r - 4.3) / 0.7, 2))
        const kick = journey.current.kick || 0
        if (kick > 0) { warpAmt = Math.max(warpAmt, kick); journey.current.kick = Math.max(0, kick - dt * 1.5) }
      }
      camera.position.set(tmpP.x + spx * 1.4, tmpP.y - spy * 1.0, tmpP.z)
      camera.lookAt(tmpL)
      if (roll) camera.rotateZ(roll)
      const fovT = 50 + warpAmt * 22
      if (Math.abs(camera.fov - fovT) > 0.05) { camera.fov = fovT; camera.updateProjectionMatrix() }
      warpU.uWarp.value = warpAmt
      group.rotation.y += warpAmt * dt * 2.2
      const cp = 1 + 0.07 * Math.sin(time * 2.4)
      coreMesh.scale.setScalar(cp); coreFill.scale.setScalar(cp * (1 + uniforms.uAlert.value * 0.15 * Math.sin(time * 12)))
      coreMesh.rotation.y = time * 0.5; coreMesh.rotation.x = time * 0.22
      coreMat.color.copy(colA); coreFill.material.color.copy(colB)
      dust.rotation.y = time * 0.01
      bloom.strength = 0.85 + uniforms.uAlert.value * 0.5 + Math.sin(time * 0.8) * 0.06 + warpAmt * 0.35 + shell * 0.4
      // inflow streams
      const ip = inGeo.attributes.position
      for (let i = 0; i < IN; i++) {
        inR[i] -= inSp[i] * dt * speed
        if (inR[i] < 6.6) inR[i] = 20 + Math.random() * 4
        const r = inR[i], d = inDir[i], sw = time * 0.25 + i
        ip.setXYZ(i, d.x * r + Math.sin(sw) * 0.3, d.y * r, d.z * r + Math.cos(sw) * 0.3)
      }
      ip.needsUpdate = true; inMat.color.copy(colB)
      sats.forEach((s) => {
        s.a += dt * s.sp * speed
        s.m.position.set(Math.cos(s.a) * s.r, Math.sin(s.a * 0.7 + s.ph) * s.r * 0.35 * Math.sin(s.inc), Math.sin(s.a) * s.r)
        s.m.rotation.x += dt; s.m.rotation.y += dt * 1.3
      })
      satMat.color.copy(colB)
      grid.position.z = (time * 1.4) % 2.5
      grid.material.color.copy(colA)

      if (visibleNow) composer.render()
    }
    raf = requestAnimationFrame(tick)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('resize', onResize)
      document.removeEventListener('visibilitychange', onVis)
      composer.dispose(); renderer.dispose()
      scene.traverse((o) => { o.geometry?.dispose?.(); o.material?.dispose?.() })
      mount.removeChild(renderer.domElement)
      apiRef.current = {}
    }
  }, [])

  return <div ref={mountRef} className={`cm-field${visible ? '' : ' off'}`} aria-hidden="true" />
}
