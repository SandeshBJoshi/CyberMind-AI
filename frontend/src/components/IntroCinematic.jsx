import { useEffect, useRef, useState } from 'react'
import * as THREE from 'three'
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js'
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js'
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js'
import { OutputPass } from 'three/examples/jsm/postprocessing/OutputPass.js'

/**
 * IntroCinematic — a ~14 s 3D story that explains the product before the admin login:
 *   01 OBSERVE   telemetry streams in            (behavioral telemetry)
 *   02 DETECT    an Isolation Forest slices space until one session stands alone
 *   03 LOCK DOWN the session is caged — automated lockdown
 *   04 CYBERMIND AI   the neural core forms — SYSTEM SECURE
 * Contract (same as before): onFadeStart() when the exit begins, onComplete() when it is gone.
 */
const DUR = 14.6
const OUT = new THREE.Vector3(5.6, 2.3, -1.2) // the anomalous session

const CHAPTERS = [
  { t: 0, id: '01', tag: 'OBSERVE', line: 'Every keystroke tells a story.', sub: 'Behavioral telemetry · live' },
  { t: 3.4, id: '02', tag: 'DETECT', line: 'Anomalies isolate themselves.', sub: 'Isolation Forest · path length 3' },
  { t: 7.0, id: '03', tag: 'LOCK DOWN', line: 'Milliseconds, not minutes.', sub: 'Automated session lockdown' },
]
const LOG = [
  [0.5, '', 'telemetry bus online · 1,284 sessions'],
  [1.4, '', 'keystroke_rhythm baseline learned'],
  [2.3, '', 'ip_change ledger synchronised'],
  [3.8, 'warn', 'session 9f3a21c4 · keystroke_rhythm Δ 0.91'],
  [4.6, 'warn', 'rule: failed_login_burst ×6 / 10 min'],
  [5.3, 'crit', 'ml_anomaly = true · score 0.87'],
  [6.2, 'crit', 'isolated in 3 cuts'],
  [7.1, 'crit', 'LOCKDOWN triggered · session 9f3a21c4'],
  [8.0, 'ok', 'protected actions blocked · admin unlock required'],
  [9.1, 'ok', 'threat contained · 0 bytes exfiltrated'],
  [10.5, 'ok', 'CYBERMIND CORE ENGAGED — SYSTEM SECURE'],
]
const GLYPHS = '!<>-_\\/[]{}—=+*^?#'

const smooth = (a, b, x) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t) }
const easeOutBack = (t) => { const c1 = 1.70158, c3 = c1 + 1; return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2) }

function fib(n, r, jitter = 0.03) {
  const out = new Float32Array(n * 3)
  for (let i = 0; i < n; i++) {
    const k = i + 0.5, phi = Math.acos(1 - (2 * k) / n), th = Math.PI * (1 + Math.sqrt(5)) * k
    const rr = r * (1 - jitter / 2 + Math.random() * jitter)
    out.set([rr * Math.cos(th) * Math.sin(phi), rr * Math.sin(th) * Math.sin(phi), rr * Math.cos(phi)], i * 3)
  }
  return out
}

const NODE_COMMON = /* glsl */`
  uniform float uTime, uNodes, uMorph;
  float hash(vec3 p){ return fract(sin(dot(p, vec3(12.9898,78.233,37.719))) * 43758.5453); }
  vec3 formPos(vec3 c, vec3 s){
    float sd = hash(c);
    vec3 p = mix(c, s, smoothstep(0., 1., uMorph));
    float tr = sin(3.14159 * clamp(uMorph, 0., 1.));
    p += tr * 2.6 * vec3(sin(sd*40.+uTime*2.), cos(sd*30.+uTime*1.7), sin(sd*50.+uTime*1.3));
    p *= 1. + (1. - uNodes) * 2.6;
    p += .08 * vec3(sin(uTime*.8+sd*20.), cos(uTime*.7+sd*17.), sin(uTime*.9+sd*13.));
    return p;
  }
`

export default function IntroCinematic({ onFadeStart, onComplete }) {
  const mountRef = useRef(null)
  const flashRef = useRef(null)
  const doneRef = useRef(false)
  const exitRef = useRef(() => {})
  const [chapter, setChapter] = useState(0)
  const [logs, setLogs] = useState([])
  const [showTitle, setShowTitle] = useState(false)
  const [title, setTitle] = useState('')
  const [phase, setPhase] = useState('play') // play | out
  const [clock, setClock] = useState(0)

  // ---- title scramble ----
  useEffect(() => {
    if (!showTitle) return
    const text = 'CYBERMIND'
    let f = 0
    const id = setInterval(() => {
      const p = f / 26
      setTitle([...text].map((c, i) => (i < text.length * p ? c : GLYPHS[(Math.random() * GLYPHS.length) | 0])).join(''))
      if (f++ >= 26) { clearInterval(id); setTitle(text) }
    }, 34)
    return () => clearInterval(id)
  }, [showTitle])

  useEffect(() => {
    const mount = mountRef.current
    const small = window.innerWidth < 760
    let renderer
    try {
      renderer = new THREE.WebGLRenderer({ antialias: false, powerPreference: 'high-performance' })
    } catch {
      // No WebGL: show the text-only version for a moment, then continue
      const id = setTimeout(() => exitRef.current(true), 2500)
      return () => clearTimeout(id)
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, small ? 1.25 : 1.6))
    renderer.setSize(mount.clientWidth, mount.clientHeight)
    renderer.toneMapping = THREE.ACESFilmicToneMapping
    renderer.setClearColor(0x04050a, 1)
    mount.appendChild(renderer.domElement)

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(55, mount.clientWidth / mount.clientHeight, 0.1, 300)
    camera.position.set(0, 0.4, 14)

    const U = {
      uTime: { value: 0 }, uNodes: { value: 0 }, uMorph: { value: 0 }, uPx: { value: renderer.getPixelRatio() },
      uAlert: { value: 0 }, uOutDie: { value: 0 }, uEdges: { value: 0 },
      uBoxMin: { value: new THREE.Vector3(-99, -99, -99) }, uBoxMax: { value: new THREE.Vector3(99, 99, 99) },
    }

    // ================= nodes (normal sessions) =================
    const N = small ? 700 : 1500
    const cloud = new Float32Array(N * 3), sphere = new Float32Array(N * 3)
    const N1 = Math.floor(N * 0.76)
    sphere.set(fib(N1, 7), 0); sphere.set(fib(N - N1, 4.3), N1 * 3)
    for (let i = 0; i < N; i++) {
      // blob: random direction * cube-root radius, a little flattened
      let x, y, z, l
      do { x = Math.random() * 2 - 1; y = Math.random() * 2 - 1; z = Math.random() * 2 - 1; l = x * x + y * y + z * z } while (l > 1 || l < 1e-3)
      const r = 4.4 * Math.cbrt(Math.random()) / Math.sqrt(l)
      cloud.set([x * r, y * r * 0.82, z * r], i * 3)
    }
    cloud.set([OUT.x, OUT.y, OUT.z], 0) // index 0 = the anomalous session
    sphere.set([OUT.x, OUT.y, OUT.z], 0)
    const pal = ['#5ee1ff', '#8f8bff', '#6aa8ff', '#b79bff'].map((c) => new THREE.Color(c))
    const col = new Float32Array(N * 3), size = new Float32Array(N), isOut = new Float32Array(N)
    for (let i = 0; i < N; i++) { const c = pal[(Math.random() * pal.length) | 0]; col.set([c.r, c.g, c.b], i * 3); size[i] = Math.random() < 0.05 ? 3 + Math.random() * 2 : 0.9 + Math.random() * 1.3 }
    isOut[0] = 1

    const ng = new THREE.BufferGeometry()
    ng.setAttribute('position', new THREE.BufferAttribute(cloud, 3))
    ng.setAttribute('aC', new THREE.BufferAttribute(cloud, 3))
    ng.setAttribute('aS', new THREE.BufferAttribute(sphere, 3))
    ng.setAttribute('aCol', new THREE.BufferAttribute(col, 3))
    ng.setAttribute('aSize', new THREE.BufferAttribute(size, 1))
    ng.setAttribute('aOut', new THREE.BufferAttribute(isOut, 1))
    const nodes = new THREE.Points(ng, new THREE.ShaderMaterial({
      uniforms: U, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
      vertexShader: `${NODE_COMMON}
        uniform float uPx, uAlert, uOutDie; uniform vec3 uBoxMin, uBoxMax;
        attribute vec3 aC, aS, aCol; attribute float aSize, aOut; varying vec3 vCol; varying float vB;
        void main(){
          vec3 p = formPos(aC, aS);
          vec4 mv = modelViewMatrix * vec4(p, 1.);
          gl_Position = projectionMatrix * mv;
          bool inBox = all(greaterThan(aC, uBoxMin)) && all(lessThan(aC, uBoxMax));
          float dim = mix(inBox ? 1. : .12, 1., smoothstep(0., .3, uMorph));
          float sz = aSize; vec3 c = mix(aCol, vec3(1., .3, .45), uAlert * .55);
          float b = .6 + .4 * sin(uTime * 1.8 + hash(aC) * 50.);
          if (aOut > .5) { c = vec3(1., .16, .3); sz = 11. * (1. - uOutDie); b = 1.5 + .6 * sin(uTime * 11.); dim = 1.; }
          gl_PointSize = min(sz * uPx * (32. / -mv.z), 64.);
          vCol = c; vB = b * dim * uNodes;
        }`,
      fragmentShader: `varying vec3 vCol; varying float vB;
        void main(){ float d = length(gl_PointCoord - .5); if (d > .5) discard;
          float g = pow(1. - d * 2., 2.); gl_FragColor = vec4(vCol * (g * 1.25 + smoothstep(.16, 0., d)) * vB, 1.); }`,
    }))
    scene.add(nodes)

    // ================= synapses (visible once the core forms) =================
    const edgeSet = new Set()
    for (let i = 0; i < N1; i++) {
      let b1 = -1, b2 = -1, d1 = 1e9, d2 = 1e9
      const x = sphere[i * 3], y = sphere[i * 3 + 1], z = sphere[i * 3 + 2]
      for (let j = 0; j < N1; j++) {
        if (j === i) continue
        const dx = sphere[j * 3] - x, dy = sphere[j * 3 + 1] - y, dz = sphere[j * 3 + 2] - z, d = dx * dx + dy * dy + dz * dz
        if (d < d1) { d2 = d1; b2 = b1; d1 = d; b1 = j } else if (d < d2) { d2 = d; b2 = j }
      }
      for (const j of [b1, b2]) if (j > 0 && i > 0) edgeSet.add(i < j ? i * N + j : j * N + i)
    }
    const edges = [...edgeSet], E = edges.length
    const A = { c0: new Float32Array(E * 6), s0: new Float32Array(E * 6), c1: new Float32Array(E * 6), s1: new Float32Array(E * 6) }
    const lt = new Float32Array(E * 2), ls = new Float32Array(E * 2), lc = new Float32Array(E * 6)
    edges.forEach((key, e) => {
      const i = Math.floor(key / N), j = key % N, sd = Math.random()
      A.c0.set(cloud.subarray(i * 3, i * 3 + 3), e * 6); A.c0.set(cloud.subarray(j * 3, j * 3 + 3), e * 6 + 3)
      A.s0.set(sphere.subarray(i * 3, i * 3 + 3), e * 6); A.s0.set(sphere.subarray(j * 3, j * 3 + 3), e * 6 + 3)
      A.c1.set(cloud.subarray(j * 3, j * 3 + 3), e * 6); A.c1.set(cloud.subarray(i * 3, i * 3 + 3), e * 6 + 3)
      A.s1.set(sphere.subarray(j * 3, j * 3 + 3), e * 6); A.s1.set(sphere.subarray(i * 3, i * 3 + 3), e * 6 + 3)
      lt[e * 2] = 0; lt[e * 2 + 1] = 1; ls[e * 2] = sd; ls[e * 2 + 1] = sd
      lc.set(col.subarray(i * 3, i * 3 + 3), e * 6); lc.set(col.subarray(j * 3, j * 3 + 3), e * 6 + 3)
    })
    const eg = new THREE.BufferGeometry()
    eg.setAttribute('position', new THREE.BufferAttribute(A.c0, 3))
    eg.setAttribute('aC0', new THREE.BufferAttribute(A.c0, 3)); eg.setAttribute('aS0', new THREE.BufferAttribute(A.s0, 3))
    eg.setAttribute('aC1', new THREE.BufferAttribute(A.c1, 3)); eg.setAttribute('aS1', new THREE.BufferAttribute(A.s1, 3))
    eg.setAttribute('aT', new THREE.BufferAttribute(lt, 1)); eg.setAttribute('aSd', new THREE.BufferAttribute(ls, 1))
    eg.setAttribute('aCol', new THREE.BufferAttribute(lc, 3))
    const lines = new THREE.LineSegments(eg, new THREE.ShaderMaterial({
      uniforms: U, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
      vertexShader: `${NODE_COMMON}
        uniform float uEdges; attribute vec3 aC0, aS0, aC1, aS1, aCol; attribute float aT, aSd;
        varying vec3 vCol; varying float vA, vT, vSd;
        void main(){
          vec3 p = formPos(aC0, aS0), q = formPos(aC1, aS1);
          vA = smoothstep(3.4, .9, length(p - q)) * uEdges;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.);
          vCol = aCol; vT = aT; vSd = aSd;
        }`,
      fragmentShader: `uniform float uTime; varying vec3 vCol; varying float vA, vT, vSd;
        void main(){ float x = fract(uTime * .25 + vSd * 9.); float pulse = smoothstep(.13, 0., abs(vT - x));
          gl_FragColor = vec4(vCol * (.09 + pulse * 1.6) * vA, 1.); }`,
    }))
    scene.add(lines)

    // ================= telemetry streaks (chapter 01) =================
    const S = small ? 500 : 1000
    const sp = new Float32Array(S * 6), sSeed = new Float32Array(S * 2), sT = new Float32Array(S * 2), sCol = new Float32Array(S * 6)
    const c1 = new THREE.Color('#5ee1ff'), c2 = new THREE.Color('#8f8bff')
    for (let i = 0; i < S; i++) {
      const a = Math.random() * Math.PI * 2, r = 3.6 + Math.pow(Math.random(), 0.8) * 8.5, z = Math.random() * 80, sd = Math.random()
      const x = Math.cos(a) * r, y = Math.sin(a) * r
      sp.set([x, y, z, x, y, z], i * 6); sSeed[i * 2] = sd; sSeed[i * 2 + 1] = sd; sT[i * 2] = 0; sT[i * 2 + 1] = 1
      const c = Math.random() < 0.6 ? c1 : c2; sCol.set([c.r, c.g, c.b, c.r, c.g, c.b], i * 6)
    }
    const sg = new THREE.BufferGeometry()
    sg.setAttribute('position', new THREE.BufferAttribute(sp, 3)); sg.setAttribute('aP', new THREE.BufferAttribute(sp, 3))
    sg.setAttribute('aSeed', new THREE.BufferAttribute(sSeed, 1)); sg.setAttribute('aT', new THREE.BufferAttribute(sT, 1))
    sg.setAttribute('aCol', new THREE.BufferAttribute(sCol, 3))
    const SU = { uTime: U.uTime, uSpeed: { value: 30 }, uLen: { value: 6 }, uStreamA: { value: 1 } }
    const streams = new THREE.LineSegments(sg, new THREE.ShaderMaterial({
      uniforms: SU, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
      vertexShader: `uniform float uTime, uSpeed, uLen, uStreamA; attribute vec3 aP, aCol; attribute float aSeed, aT; varying vec3 vCol; varying float vA;
        void main(){
          float z = mod(aP.z + uTime * uSpeed * (.5 + aSeed), 80.) - 55.;
          vec3 p = vec3(aP.xy, z - aT * uLen * (.35 + aSeed));
          gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.);
          vA = uStreamA * smoothstep(-55., -38., z) * smoothstep(24., 8., z) * (1. - aT * .85); vCol = aCol;
        }`,
      fragmentShader: `varying vec3 vCol; varying float vA; void main(){ gl_FragColor = vec4(vCol * vA * 0.72, 1.); }`,
    }))
    scene.add(streams)

    // ================= isolation-forest cuts =================
    const cutDefs = [
      { t: 4.4, axis: 'x', v: 3.4 }, { t: 5.2, axis: 'y', v: 1.4 }, { t: 6.0, axis: 'x', v: 4.8 },
    ]
    const cuts = cutDefs.map((c) => {
      const g = new THREE.Group()
      const plane = new THREE.Mesh(new THREE.PlaneGeometry(11, 11), new THREE.MeshBasicMaterial({ color: 0x5ee1ff, transparent: true, opacity: 0.035, side: THREE.DoubleSide, depthWrite: false, blending: THREE.AdditiveBlending }))
      const frame = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(11, 11)), new THREE.LineBasicMaterial({ color: 0x9be9ff, transparent: true, opacity: 0.7, blending: THREE.AdditiveBlending }))
      g.add(plane, frame)
      if (c.axis === 'x') { g.rotation.y = Math.PI / 2; g.position.x = c.v } else { g.rotation.x = Math.PI / 2; g.position.y = c.v }
      g.scale.set(0, 0, 1); scene.add(g)
      return { g, def: c, planeMat: plane.material, frameMat: frame.material }
    })

    // ================= lockdown cage + shockwave =================
    const cage = new THREE.Group(); cage.position.copy(OUT); cage.visible = false
    const cageWire = new THREE.Mesh(new THREE.IcosahedronGeometry(1.35, 1), new THREE.MeshBasicMaterial({ color: 0xff4d73, wireframe: true, transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending }))
    const cageFill = new THREE.Mesh(new THREE.IcosahedronGeometry(1.3, 1), new THREE.MeshBasicMaterial({ color: 0xff2a55, transparent: true, opacity: 0.12, blending: THREE.AdditiveBlending, depthWrite: false }))
    const rings = [0, 1, 2].map((i) => { const r = new THREE.Mesh(new THREE.TorusGeometry(1.95 + i * 0.25, 0.014, 8, 96), new THREE.MeshBasicMaterial({ color: 0xff7a8f, transparent: true, opacity: 0.8, blending: THREE.AdditiveBlending })); r.rotation.set(i * 1.05, i * 0.7, 0); cage.add(r); return r })
    cage.add(cageWire, cageFill); scene.add(cage)
    const shock = new THREE.Mesh(new THREE.RingGeometry(0.92, 1, 96), new THREE.MeshBasicMaterial({ color: 0xff4d73, transparent: true, opacity: 0, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }))
    shock.position.copy(OUT); scene.add(shock)
    const shock2 = new THREE.Mesh(new THREE.RingGeometry(0.94, 1, 96), new THREE.MeshBasicMaterial({ color: 0x8f8bff, transparent: true, opacity: 0, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }))
    scene.add(shock2)

    // ================= dust =================
    const DN = small ? 400 : 1100, dp = new Float32Array(DN * 3)
    for (let i = 0; i < DN; i++) dp.set([(Math.random() - 0.5) * 120, (Math.random() - 0.5) * 80, (Math.random() - 0.5) * 120], i * 3)
    const dg = new THREE.BufferGeometry(); dg.setAttribute('position', new THREE.BufferAttribute(dp, 3))
    const dust = new THREE.Points(dg, new THREE.PointsMaterial({ color: 0x6f7bff, size: 0.1, transparent: true, opacity: 0.5, depthWrite: false, blending: THREE.AdditiveBlending }))
    scene.add(dust)

    // ================= post =================
    const composer = new EffectComposer(renderer)
    composer.addPass(new RenderPass(scene, camera))
    const bloom = new UnrealBloomPass(new THREE.Vector2(mount.clientWidth, mount.clientHeight), 0.7, 0.45, 0.22)
    composer.addPass(bloom); composer.addPass(new OutputPass())

    // ================= camera director =================
    const tmpA = new THREE.Vector3(), tmpB = new THREE.Vector3()
    const orbitPos = (t) => {
      const a = 0.075 + (t - 7) * 0.8, r = 8 - (t - 7) * 0.75
      return tmpA.set(OUT.x + Math.sin(a) * r, OUT.y + 0.3 + (t - 7) * 0.35, OUT.z + Math.cos(a) * r)
    }
    function director(t, pos, look) {
      if (t < 3.4) { // fly down the telemetry tunnel
        const k = smooth(0, 3.4, t)
        pos.set(Math.sin(t * 0.5) * 0.6, 0.4, 14 - k * 1.0); look.set(0, 0, -30 + k * 30)
      } else if (t < 6.2) { // watch the cloud, slide toward the anomaly
        const k = smooth(3.4, 6.2, t)
        pos.set(k * 6.4, 0.6 + k * 2.2, 13 - k * 2.4); look.set(OUT.x * k, OUT.y * k * 0.9, OUT.z * k)
      } else if (t < 7.0) { // punch in
        const k = smooth(6.2, 7.0, t)
        const o = orbitPos(7); pos.set(6.4 + (o.x - 6.4) * k, 2.8 + (o.y - 2.8) * k, 10.6 + (o.z - 10.6) * k); look.copy(OUT)
      } else if (t < 9.6) { // orbit the caged session
        pos.copy(orbitPos(t)); look.copy(OUT)
      } else { // pull back to reveal the core
        const from = orbitPos(9.6); tmpB.copy(from)
        const k = smooth(9.6, 11.6, t)
        pos.set(tmpB.x + (0 - tmpB.x) * k, tmpB.y + (1.6 - tmpB.y) * k, tmpB.z + (23 - tmpB.z) * k)
        look.set(OUT.x * (1 - k), OUT.y * (1 - k), OUT.z * (1 - k))
        if (t > 11.6) { const y = (t - 11.6) * 0.1; const x = pos.x, z = pos.z; pos.x = x * Math.cos(y) + z * Math.sin(y); pos.z = -x * Math.sin(y) + z * Math.cos(y) }
      }
    }

    // ================= clock / timeline =================
    let start = performance.now(), raf = 0, running = true, last = start
    let logIdx = 0, chIdx = 0, flashed = false, titled = false, finished = false
    let skipBoost = Number(new URLSearchParams(window.location.search).get('introT')) || 0 // debug: ?introT=10 starts mid-timeline
    const pos = new THREE.Vector3(), look = new THREE.Vector3()
    const boxMinT = new THREE.Vector3(-99, -99, -99), boxMaxT = new THREE.Vector3(99, 99, 99)

    const tick = (now) => {
      raf = requestAnimationFrame(tick)
      if (!running) return
      const dtReal = Math.min((now - last) / 1000, 0.05); last = now
      const t = (now - start) / 1000 + skipBoost
      U.uTime.value += dtReal

      // schedule → uniforms
      SU.uStreamA.value = 1 - smooth(2.6, 3.8, t)
      SU.uSpeed.value = 34 - 26 * smooth(1.6, 3.6, t)
      SU.uLen.value = 2 + 6 * (SU.uSpeed.value / 34)
      U.uNodes.value = smooth(2.3, 3.9, t)
      U.uMorph.value = smooth(9.9, 11.7, t)
      U.uEdges.value = smooth(10.8, 12.4, t)
      U.uAlert.value = smooth(7, 7.12, t) * (1 - smooth(9.2, 9.8, t))
      U.uOutDie.value = smooth(9.3, 9.95, t)

      // isolation box narrows with each cut, relaxes after lockdown
      boxMinT.set(-99, -99, -99); boxMaxT.set(99, 99, 99)
      if (t >= 4.6 && t < 7) boxMinT.x = 3.4
      if (t >= 5.4 && t < 7) boxMinT.y = 1.4
      if (t >= 6.2 && t < 7) boxMinT.x = 4.8
      U.uBoxMin.value.lerp(boxMinT, 0.12); U.uBoxMax.value.lerp(boxMaxT, 0.12)

      cuts.forEach(({ g, def, planeMat, frameMat }) => {
        const k = smooth(def.t, def.t + 0.5, t) * (1 - smooth(6.7, 7.1, t))
        g.scale.set(k, k, 1); g.visible = k > 0.001
        planeMat.opacity = 0.035 * k; frameMat.opacity = 0.7 * k
      })

      // cage
      const caged = t >= 7.0 && t < 9.98
      cage.visible = caged
      if (caged) {
        const born = Math.min(1, (t - 7.0) / 0.5)
        const s = (4 - 3 * easeOutBack(born)) * (1 - smooth(9.3, 9.95, t))
        cage.scale.setScalar(Math.max(0.0001, s))
        cage.rotation.y = U.uTime.value * 0.9; cage.rotation.x = U.uTime.value * 0.4
        rings.forEach((r, i) => { r.rotation.z = U.uTime.value * (0.8 + i * 0.4) })
        cageFill.material.opacity = 0.1 + 0.07 * Math.sin(U.uTime.value * 9)
      }
      const sw = (t - 7.0) / 1.1
      shock.material.opacity = sw > 0 && sw < 1 ? (1 - sw) * 0.9 : 0
      shock.scale.setScalar(1 + Math.max(0, sw) * 15); shock.quaternion.copy(camera.quaternion)
      const sw2 = (t - 10.4) / 1.6
      shock2.material.opacity = sw2 > 0 && sw2 < 1 ? (1 - sw2) * 0.6 : 0
      shock2.scale.setScalar(1 + Math.max(0, sw2) * 26); shock2.quaternion.copy(camera.quaternion)

      // camera
      director(t, pos, look)
      if (t > 7.0 && t < 7.7) { const a = (1 - (t - 7) / 0.7) * 0.18; pos.x += (Math.random() - 0.5) * a; pos.y += (Math.random() - 0.5) * a }
      camera.position.copy(pos); camera.lookAt(look)
      dust.rotation.y += dtReal * 0.01
      bloom.strength = 0.65 + 0.75 * Math.max(0, 1 - Math.abs(t - 7.05) * 3) + 0.35 * smooth(10, 12, t)

      composer.render()

      // HUD triggers (React state only on change)
      setClock((c) => (Math.abs(c - t) > 0.2 ? t : c))
      while (logIdx < LOG.length && t >= LOG[logIdx][0]) { const l = LOG[logIdx]; const key = logIdx; logIdx++; setLogs((p) => [...p, { cls: l[1], text: l[2], k: key }].slice(-6)) }
      let ci = 0; CHAPTERS.forEach((c, i) => { if (t >= c.t) ci = i })
      if (t >= 10.2) ci = 3
      if (ci !== chIdx) { chIdx = ci; setChapter(ci) }
      if (!flashed && t >= 7.0) { flashed = true; flashRef.current?.classList.add('go') }
      if (!titled && t >= 10.3) { titled = true; setShowTitle(true) }
      if (!finished && t >= DUR) { finished = true; exitRef.current(false) }
    }
    raf = requestAnimationFrame(tick)

    exitRef.current = (fast) => {
      if (doneRef.current) return
      doneRef.current = true
      setPhase('out'); onFadeStart?.()
      setTimeout(() => onComplete?.(), fast ? 700 : 1100)
    }

    const onResize = () => {
      const w = mount.clientWidth, h = mount.clientHeight
      renderer.setSize(w, h); composer.setSize(w, h); camera.aspect = w / h; camera.updateProjectionMatrix()
    }
    let hiddenAt = 0
    const onVis = () => {
      if (document.hidden) { running = false; hiddenAt = performance.now() }
      else { const n = performance.now(); start += n - hiddenAt; last = n; running = true }
    }
    window.addEventListener('resize', onResize)
    document.addEventListener('visibilitychange', onVis)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', onResize)
      document.removeEventListener('visibilitychange', onVis)
      composer.dispose(); renderer.dispose()
      scene.traverse((o) => { o.geometry?.dispose?.(); o.material?.dispose?.() })
      if (renderer.domElement.parentNode === mount) mount.removeChild(renderer.domElement)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    const skip = () => exitRef.current(true)
    window.addEventListener('keydown', skip)
    return () => window.removeEventListener('keydown', skip)
  }, [])

  const ch = CHAPTERS[Math.min(chapter, 2)]
  const tc = `${String(Math.floor(clock / 60)).padStart(2, '0')}:${String(Math.floor(clock % 60)).padStart(2, '0')}`

  return (
    <div className={`cine ${phase}`}>
      <div className="cine-canvas" ref={mountRef} />
      <div className="cine-vignette" />
      <div className="cine-flash" ref={flashRef} />
      <div className="cine-bar top" /><div className="cine-bar bottom" />

      <header className="cine-top mono">
        <span><i className="cm-dot" /> CYBERMIND AI · THREAT DETECTION SYSTEM</span>
        <span className="cine-rec">● REC {tc}</span>
      </header>

      {!showTitle && (
        <div className="cine-chapter" key={chapter}>
          <b className="mono">{ch.id}</b>
          <h2 className={chapter === 2 ? 'red' : ''}>{ch.tag}</h2>
          <p>{ch.line}</p>
          <small className="mono">{ch.sub}</small>
        </div>
      )}

      <ul className="cine-log mono">
        {logs.map((l) => <li key={l.k} className={l.cls}>{l.text}</li>)}
      </ul>

      {showTitle && (
        <div className="cine-title">
          <div className="mono cine-title-k">BEHAVIORAL THREAT PROTECTION</div>
          <h1>{title || 'CYBERMIND'}<span> AI</span></h1>
          <p>The mind that never blinks.</p>
          <div className="cine-chips mono"><span>CYBERMIND CORE ENGAGED</span><span className="ok">SYSTEM SECURE</span></div>
        </div>
      )}

      <footer className="cine-foot">
        <div className="cine-ticks">
          {[0, 1, 2, 3].map((i) => <i key={i} className={i <= chapter ? 'on' : ''} />)}
        </div>
        <div className="cine-skips">
        <button className="cine-skip mono" onClick={() => exitRef.current(true)}>SKIP INTRO · any key</button>
        <button className="cine-skip cine-skip-always mono" onClick={() => { try { window.localStorage.setItem('cm_skip_intro', '1') } catch { /* ignore */ } exitRef.current(true) }}>ALWAYS SKIP</button>
        </div>
      </footer>
    </div>
  )
}
