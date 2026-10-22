/**
 * ShatteredGlassHero — "Broken by Design" style hero section
 * Inspired by Guglielmo Giannattasio (21st.dev ID 24794)
 * All CSS classes prefixed .sgh- — zero collision with existing project styles
 */
import { useEffect, useRef, useState } from "react"

// ─── 16 shard pieces in 3 rings ────────────────────────────────────────────
const PIECES = [
  { id: 0,  x: 28, y: 20, w: 44, h: 42, ring: 0 },
  { id: 1,  x:  0, y:  0, w: 30, h: 35, ring: 1 },
  { id: 2,  x: 70, y:  0, w: 30, h: 38, ring: 1 },
  { id: 3,  x:  0, y: 55, w: 28, h: 45, ring: 1 },
  { id: 4,  x: 72, y: 52, w: 28, h: 48, ring: 1 },
  { id: 5,  x: 22, y: 78, w: 56, h: 22, ring: 1 },
  { id: 6,  x:  0, y: 33, w: 20, h: 22, ring: 2 },
  { id: 7,  x: 80, y: 36, w: 20, h: 16, ring: 2 },
  { id: 8,  x: 28, y:  0, w: 18, h: 22, ring: 2 },
  { id: 9,  x: 54, y:  0, w: 16, h: 20, ring: 2 },
  { id: 10, x:  4, y: 78, w: 18, h: 22, ring: 2 },
  { id: 11, x: 78, y: 76, w: 18, h: 24, ring: 2 },
  { id: 12, x: 20, y: 62, w: 14, h: 18, ring: 2 },
  { id: 13, x: 66, y: 60, w: 14, h: 18, ring: 2 },
  { id: 14, x: 38, y: 68, w: 12, h: 16, ring: 2 },
  { id: 15, x: 50, y: 66, w: 12, h: 16, ring: 2 },
]

function seededJitter(seed) {
  const s = Math.sin(seed * 127.1 + 311.7) * 43758.5453
  return s - Math.floor(s)
}

const JITTERS = PIECES.map((_, i) => ({
  tx:  (seededJitter(i * 3 + 0) - 0.5) * 6,
  ty:  (seededJitter(i * 3 + 1) - 0.5) * 6,
  rot: (seededJitter(i * 3 + 2) - 0.5) * 4,
}))

const CLIP_PATHS = [
  "polygon(4% 2%, 98% 0%, 96% 98%, 2% 96%)",
  "polygon(0% 0%, 100% 5%, 96% 100%, 0% 92%)",
  "polygon(4% 0%, 100% 0%, 100% 95%, 6% 100%)",
  "polygon(0% 2%, 100% 0%, 94% 98%, 0% 100%)",
  "polygon(6% 0%, 100% 4%, 100% 100%, 2% 96%)",
  "polygon(0% 0%, 100% 5%, 98% 100%, 2% 94%)",
  "polygon(0% 0%, 100% 8%, 92% 100%, 0% 100%)",
  "polygon(8% 0%, 100% 0%, 100% 100%, 0% 92%)",
  "polygon(5% 0%, 95% 0%, 100% 100%, 0% 100%)",
  "polygon(0% 0%, 100% 5%, 95% 100%, 5% 100%)",
  "polygon(0% 0%, 92% 5%, 100% 100%, 8% 98%)",
  "polygon(8% 0%, 100% 2%, 96% 100%, 0% 96%)",
  "polygon(0% 8%, 100% 0%, 96% 92%, 4% 100%)",
  "polygon(4% 0%, 100% 8%, 92% 100%, 0% 96%)",
  "polygon(0% 4%, 96% 0%, 100% 96%, 4% 100%)",
  "polygon(4% 0%, 100% 4%, 96% 100%, 0% 100%)",
]

const CRACK_MAIN = [
  "M28,20 L0,0 M28,20 L72,20 M28,20 L0,35",
  "M72,20 L100,0 M72,20 L100,38",
  "M28,62 L0,55 M28,62 L0,78",
  "M72,62 L100,52 M72,62 L100,76",
  "M28,78 L22,100 M72,78 L78,100",
  "M28,20 L28,62 M72,20 L72,62",
]
const CRACK_FINE = [
  "M14,17 L0,33 M14,17 L28,20",
  "M86,18 L100,36 M86,18 L72,20",
  "M10,89 L0,78 M10,89 L22,100",
  "M89,88 L100,76 M89,88 L78,100",
  "M42,6 L28,0 M42,6 L54,0",
  "M50,72 L38,84 M50,72 L62,84",
]

function toTx({ rx, ry, tz, px, py, sc }) {
  return `translate(${px.toFixed(2)}px,${py.toFixed(2)}px) rotateX(${rx.toFixed(2)}deg) rotateY(${ry.toFixed(2)}deg) translateZ(${tz.toFixed(2)}px) scale(${sc.toFixed(4)})`
}

function baseOf(id) {
  const j = JITTERS[id]
  return { rx: j.rot * 0.5, ry: j.rot * 0.7, tz: (2 - PIECES[id].ring) * 8, px: j.tx, py: j.ty, sc: 1.0 }
}

function playCrack(ctx) {
  try {
    const buf = ctx.createBuffer(1, ctx.sampleRate * 0.08, ctx.sampleRate)
    const d = buf.getChannelData(0)
    for (let i = 0; i < d.length; i++) d[i] = (Math.random() * 2 - 1) * Math.exp(-i / (ctx.sampleRate * 0.015))
    const src = ctx.createBufferSource()
    src.buffer = buf
    const g = ctx.createGain(); g.gain.value = 0.18
    const bpf = ctx.createBiquadFilter(); bpf.type = "bandpass"; bpf.frequency.value = 3200; bpf.Q.value = 0.8
    src.connect(bpf); bpf.connect(g); g.connect(ctx.destination)
    src.start()
  } catch {}
}

const SGH_CSS = `
@import url("https://fonts.googleapis.com/css2?family=Inter:wght@300;700;900&display=swap");
.sgh-root{position:relative;width:100%;background:transparent !important;overflow:visible;display:flex;align-items:center;justify-content:center;perspective:900px;cursor:default;user-select:none;border:none !important;box-shadow:none !important}
.sgh-bg{display:none !important}
.sgh-stage{position:relative;width:min(640px,90vw);aspect-ratio:16/10;transform-style:preserve-3d}
.sgh-under{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;pointer-events:none;z-index:1}
.sgh-l1{font-family:"Inter",sans-serif;font-weight:900;font-size:clamp(2.6rem,7vw,4.8rem);letter-spacing:-.04em;text-transform:uppercase;color:rgba(0,255,120,.07);line-height:1}
.sgh-l2{font-family:"Inter",sans-serif;font-weight:300;font-size:clamp(.65rem,1.5vw,.95rem);letter-spacing:.35em;text-transform:uppercase;color:rgba(0,255,120,.05)}
.sgh-cracks{position:absolute;inset:0;width:100%;height:100%;pointer-events:none;z-index:2}
.sgh-cracks .glow path{fill:none;stroke:rgba(0,255,100,.45);stroke-width:3.5;filter:blur(4px)}
.sgh-cracks .line path{fill:none;stroke:rgba(180,255,200,.65);stroke-width:.6}
.sgh-cracks .fine path{fill:none;stroke:rgba(140,255,180,.35);stroke-width:.3;stroke-dasharray:3 4}
.sgh-pane{position:absolute;inset:0;transform-style:preserve-3d;z-index:3}
.sgh-shard{position:absolute;transform-style:preserve-3d}
.sgh-inlay{width:100%;height:100%;position:relative;overflow:hidden;border-radius:1px}
.sgh-glass{position:absolute;inset:0;background:linear-gradient(135deg,rgba(0,255,130,.13) 0%,rgba(0,200,100,.06) 40%,rgba(0,80,50,.04) 70%,rgba(0,30,20,.08) 100%);backdrop-filter:blur(6px) saturate(1.4);-webkit-backdrop-filter:blur(6px) saturate(1.4);border:.5px solid rgba(0,255,120,.18)}
.sgh-slice{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;overflow:hidden;pointer-events:none}
.sgh-slice .sgh-l1{background:linear-gradient(180deg,rgba(180,255,210,.95) 0%,rgba(0,255,130,.8) 50%,rgba(0,160,80,.55) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;filter:drop-shadow(0 0 12px rgba(0,255,120,.6));color:transparent}
.sgh-slice .sgh-l2{color:rgba(120,255,180,.7)}
.sgh-spec{position:absolute;inset:0;background:radial-gradient(ellipse 120% 120% at var(--mx,30%) var(--my,25%),rgba(255,255,255,.22) 0%,rgba(0,255,120,.08) 35%,transparent 65%);pointer-events:none;mix-blend-mode:screen}
.sgh-eglow{position:absolute;inset:-1px;border-radius:1px;pointer-events:none;box-shadow:0 0 6px rgba(0,255,120,.35),inset 0 0 4px rgba(0,255,120,.12);opacity:0;transition:opacity .18s}
.sgh-shard--hot .sgh-eglow{opacity:1}
.sgh-shard--hot .sgh-glass{background:linear-gradient(135deg,rgba(0,255,130,.22) 0%,rgba(0,200,100,.12) 40%,rgba(0,80,50,.07) 70%,rgba(0,40,25,.1) 100%)}
.sgh-caption{position:absolute;bottom:-36px;left:0;right:0;text-align:center;font-family:"Inter",sans-serif;font-size:.68rem;letter-spacing:.22em;text-transform:uppercase;color:rgba(0,255,120,.3);pointer-events:none}
.sgh-sfxbtn{position:absolute;bottom:14px;right:18px;background:rgba(0,255,120,.07);border:1px solid rgba(0,255,120,.22);border-radius:7px;color:rgba(0,255,120,.65);font-size:10px;letter-spacing:.1em;text-transform:uppercase;padding:5px 11px;cursor:pointer;font-family:"Inter",sans-serif;transition:all .2s}
.sgh-sfxbtn:hover{background:rgba(0,255,120,.13);color:rgba(0,255,120,.9)}
@keyframes sgh-in{from{opacity:0;transform:var(--ini,none)}to{opacity:1}}
.sgh-ready .sgh-shard{animation:sgh-in .55s cubic-bezier(.22,1,.36,1) both;animation-delay:var(--dl,0s)}
`

export default function ShatteredGlassHero({ height = "70vh", className = "" }) {
  const rootRef   = useRef(null)
  const shardRefs = useRef([])
  const audioRef  = useRef(null)
  const soundRef  = useRef(false)
  const [soundOn, setSoundOn] = useState(false)
  const [ready,   setReady]   = useState(false)

  useEffect(() => { soundRef.current = soundOn }, [soundOn])
  useEffect(() => { const t = setTimeout(() => setReady(true), 80); return () => clearTimeout(t) }, [])

  useEffect(() => {
    if (!ready) return
    const root = rootRef.current; if (!root) return
    const shards = shardRefs.current.filter(Boolean)
    const n = shards.length
    const cur = PIECES.map(p => ({ ...baseOf(p.id) }))
    const tgt = PIECES.map(p => ({ ...baseOf(p.id) }))
    const hovered = new Set()
    let gx = 0, gy = 0, raf = 0, running = false

    function wake() { if (!running) { running = true; raf = requestAnimationFrame(tick) } }
    function tick() {
      let alive = false; const k = 0.12
      for (let i = 0; i < n; i++) {
        const c = cur[i], t = tgt[i]
        c.rx += (t.rx-c.rx)*k; c.ry += (t.ry-c.ry)*k; c.tz += (t.tz-c.tz)*k
        c.px += (t.px-c.px)*k; c.py += (t.py-c.py)*k; c.sc += (t.sc-c.sc)*k
        const d = Math.abs(t.rx-c.rx)+Math.abs(t.ry-c.ry)+Math.abs(t.tz-c.tz)+Math.abs(t.px-c.px)+Math.abs(t.py-c.py)
        if (d > 0.01) alive = true
        if (shards[i]) shards[i].style.transform = toTx(c)
      }
      if (alive) raf = requestAnimationFrame(tick); else running = false
    }
    function setParallax() {
      for (let i = 0; i < n; i++) {
        if (hovered.has(i)) continue
        const b = baseOf(PIECES[i].id), depth = 1 - PIECES[i].ring * 0.32
        tgt[i].px = b.px - gx*24*depth; tgt[i].py = b.py - gy*18*depth
        tgt[i].rx = b.rx + gy*3.2*depth; tgt[i].ry = b.ry - gx*4*depth
        tgt[i].tz = b.tz; tgt[i].sc = b.sc
      }
    }
    const onMove = e => { const r = root.getBoundingClientRect(); gx=(e.clientX-r.left)/r.width-.5; gy=(e.clientY-r.top)/r.height-.5; setParallax(); wake() }
    const onLeave = () => { gx=0; gy=0; tgt.forEach((_,i)=>{ if(!hovered.has(i)) Object.assign(tgt[i],baseOf(PIECES[i].id)) }); wake() }
    const fns = [()=>root.removeEventListener("pointermove",onMove),()=>root.removeEventListener("pointerleave",onLeave)]
    root.addEventListener("pointermove",onMove); root.addEventListener("pointerleave",onLeave)

    shards.forEach((el, i) => {
      const onSMove = e => {
        const r = el.getBoundingClientRect(), lx=(e.clientX-r.left)/r.width-.5, ly=(e.clientY-r.top)/r.height-.5
        const b = baseOf(PIECES[i].id)
        tgt[i].rx=b.rx-ly*14; tgt[i].ry=b.ry+lx*17; tgt[i].tz=b.tz+92; tgt[i].sc=1.035
        el.style.setProperty("--mx",`${((lx+.5)*100).toFixed(1)}%`); el.style.setProperty("--my",`${((ly+.5)*100).toFixed(1)}%`)
        wake()
      }
      const onEnter = () => {
        hovered.add(i); el.classList.add("sgh-shard--hot")
        if (soundRef.current) { try { audioRef.current=audioRef.current||new AudioContext(); const ctx=audioRef.current; if(ctx.state==="suspended")ctx.resume().catch(()=>{}); playCrack(ctx) } catch{} }
      }
      const onSLeave = () => { hovered.delete(i); el.classList.remove("sgh-shard--hot"); Object.assign(tgt[i],baseOf(PIECES[i].id)); setParallax(); wake() }
      el.addEventListener("pointermove",onSMove); el.addEventListener("pointerenter",onEnter); el.addEventListener("pointerleave",onSLeave)
      fns.push(()=>{el.removeEventListener("pointermove",onSMove);el.removeEventListener("pointerenter",onEnter);el.removeEventListener("pointerleave",onSLeave)})
    })
    return () => { cancelAnimationFrame(raf); fns.forEach(f=>f()) }
  }, [ready])

  const titleNode = (
    <>
      <span className="sgh-l1">CYBERMIND AI</span>
      <span className="sgh-l2">Threat Detection System</span>
    </>
  )

  return (
    <>
      <style>{SGH_CSS}</style>
      <section ref={rootRef} className={`sgh-root${ready?" sgh-ready":""} ${className}`} style={{height}} aria-label="CYBERMIND AI hero">
        <div className="sgh-stage">
          <div className="sgh-under" aria-hidden="true">{titleNode}</div>
          <svg className="sgh-cracks" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
            <g className="glow">{CRACK_MAIN.map((d,i)=><path key={i} d={d}/>)}</g>
            <g className="line">{CRACK_MAIN.map((d,i)=><path key={i} d={d}/>)}</g>
            <g className="fine">{CRACK_FINE.map((d,i)=><path key={i} d={d}/>)}</g>
          </svg>
          <div className="sgh-pane" aria-hidden="true">
            {ready && PIECES.map((p, i) => (
              <div key={p.id} ref={el=>{shardRefs.current[i]=el}} className="sgh-shard"
                style={{left:`${p.x}%`,top:`${p.y}%`,width:`${p.w}%`,height:`${p.h}%`,zIndex:10+(2-p.ring),"--dl":`${i*.04}s`,"--ini":`translate(${JITTERS[i].tx*4}px,${JITTERS[i].ty*4}px) rotateX(${JITTERS[i].rot*3}deg)`,"--mx":"30%","--my":"25%"}}>
                <div className="sgh-inlay" style={{clipPath:CLIP_PATHS[p.id]}}>
                  <div className="sgh-glass"/>
                  <div className="sgh-slice" style={{width:`${10000/p.w}%`,height:`${10000/p.h}%`,left:`${-(p.x/p.w)*100}%`,top:`${-(p.y/p.h)*100}%`,transform:`translate(${JITTERS[i].tx.toFixed(1)}px,${JITTERS[i].ty.toFixed(1)}px) rotate(${JITTERS[i].rot.toFixed(2)}deg)`}}>
                    {titleNode}
                  </div>
                  <div className="sgh-spec"/>
                  <div className="sgh-eglow"/>
                </div>
              </div>
            ))}
          </div>
          <p className="sgh-caption">Hover shards to interact</p>
        </div>
        <button type="button" className="sgh-sfxbtn" aria-pressed={soundOn} aria-label={soundOn?"Disable SFX":"Enable SFX"}
          onClick={()=>{setSoundOn(v=>!v);try{audioRef.current=audioRef.current||new AudioContext()}catch{}}}>
          {soundOn?"🔊 SFX ON":"🔇 SFX OFF"}
        </button>
      </section>
    </>
  )
}
