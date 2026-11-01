/* global document, window, ResizeObserver */
/**
 * The report page's script. report.js inlines this function's source into the
 * page, so it must stay self-contained: no imports, no outer references.
 */
export function reportPage() {
  const data = JSON.parse(document.getElementById('report-data').textContent)
  const app = document.getElementById('app')
  const tip = document.getElementById('tip')
  const SVGNS = 'http://www.w3.org/2000/svg'

  const PATHS = ['direct', 'holepunched', 'relayed']
  const PATH_VAR = {
    direct: 'var(--series-1)',
    holepunched: 'var(--series-2)',
    relayed: 'var(--series-3)'
  }
  const pathColor = (p) => PATH_VAR[p] ?? 'var(--muted)'
  const PROGRESS_SERIES = [
    ['length', 'length', 'var(--series-1)'],
    ['signedLength', 'signed', 'var(--series-2)'],
    ['indexedLength', 'indexed', 'var(--series-3)']
  ]

  // ---- helpers ----
  const svg = (tag, attrs = {}, parent = null) => {
    const node = document.createElementNS(SVGNS, tag)
    for (const [k, v] of Object.entries(attrs))
      if (v !== null && v !== undefined) node.setAttribute(k, v)
    if (parent) parent.appendChild(node)
    return node
  }
  const h = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag)
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue
      if (k === 'class') node.className = v
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v)
      else node.setAttribute(k, v === true ? '' : v)
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue
      node.appendChild(
        typeof child === 'string' || typeof child === 'number'
          ? document.createTextNode(String(child))
          : child
      )
    }
    return node
  }
  const esc = (s) =>
    String(s).replace(
      /[&<>"]/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]
    )
  const secs = (ms) => `${(ms / 1000).toFixed(ms < 10000 ? 3 : 2)} s`
  const plus = (ms) => `+${(ms / 1000).toFixed(3)}`
  const bytes = (n) =>
    n === null || n === undefined
      ? '–'
      : n < 1024
        ? `${n} B`
        : n < 1048576
          ? `${(n / 1024).toFixed(1)} KiB`
          : `${(n / 1048576).toFixed(1)} MiB`
  const fieldsText = (f) =>
    Object.entries(f)
      .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
      .join('  ')
  const niceStep = (span, target) => {
    const raw = span / Math.max(1, target)
    const pow = 10 ** Math.floor(Math.log10(raw))
    for (const m of [1, 2, 5, 10]) if (raw <= m * pow) return m * pow
    return 10 * pow
  }

  const showTip = (html, evt) => {
    tip.innerHTML = html
    tip.hidden = false
    const pad = 14
    const { innerWidth: w, innerHeight: hh } = window
    const r = tip.getBoundingClientRect()
    let x = evt.clientX + pad
    let y = evt.clientY + pad
    if (x + r.width > w - 8) x = evt.clientX - r.width - pad
    if (y + r.height > hh - 8) y = evt.clientY - r.height - pad
    tip.style.left = `${Math.max(8, x)}px`
    tip.style.top = `${Math.max(8, y)}px`
  }
  const hideTip = () => {
    tip.hidden = true
  }
  const tipHtml = (title, lines) =>
    `<div class="tt">${esc(title)}</div>${lines.map((l) => `<div class="kv">${esc(l)}</div>`).join('')}`

  // ---- state ----
  const end = Math.max(data.duration, 1)
  const state = {
    from: 0,
    to: end,
    cursor: null,
    pinned: null,
    peers: new Set(data.peers),
    family: 'all',
    text: '',
    inRange: true
  }
  const cursorT = () => state.cursor ?? state.pinned
  const redrawers = []
  const cursorers = []
  const redraw = () => redrawers.forEach((fn) => fn())
  const moveCursor = () => cursorers.forEach((fn) => fn())

  // ---- derived ----
  const peerOf = (conn) => conn.remotePeer ?? `?${conn.remote}`
  const isOpenAt = (c, t) => c.open <= t && (c.close === null || c.close > t)
  const bandAt = (peer, t) =>
    data.bands.find(
      (b) =>
        b.peer === peer &&
        !b.label &&
        b.from <= t &&
        (b.to === null || b.to > t)
    )
  const lastStep = {}
  for (const s of data.steps)
    if (s.event === 'script.step') lastStep[s.peer] = s
  const scriptEnd = {}
  for (const s of data.steps)
    if (s.event === 'script.done' || s.event === 'script.fail')
      scriptEnd[s.peer] = s

  const family = (name) => {
    if (
      name === 'error' ||
      name === 'script.fail' ||
      name.startsWith('uncaught') ||
      name.startsWith('guard') ||
      name === 'peer.stop.timeout'
    )
      return 'errors'
    if (name.startsWith('conn.') || name === 'peer.ban') return 'connections'
    if (name.startsWith('script.') || name.startsWith('peer.')) return 'steps'
    if (name.startsWith('autobase.')) return 'autobase'
    if (name.startsWith('epoch.') || name.startsWith('vault.')) return 'vault'
    return 'network'
  }

  // ---- header ----
  const header = () => {
    const statusEl = data.failed
      ? h('span', { class: 'status fail' }, '✕ Failed')
      : h('span', { class: 'status ok' }, '✓ Passed')
    const themeBtn = h(
      'button',
      {
        onclick: () => {
          const root = document.documentElement
          const dark =
            root.dataset.theme === 'dark' ||
            (!root.dataset.theme &&
              window.matchMedia('(prefers-color-scheme: dark)').matches)
          root.dataset.theme = dark ? 'light' : 'dark'
        }
      },
      'Light / dark'
    )
    const layer =
      data.topology.layer === 2
        ? 'Lab (network namespaces)'
        : 'Layer 1 (loopback testnet)'
    return h(
      'div',
      {},
      h(
        'header',
        { class: 'top' },
        h(
          'div',
          {},
          h('h1', {}, data.name),
          h(
            'div',
            { class: 'sub' },
            statusEl,
            '  ',
            `${layer} · started ${data.startWall ?? '–'} · report generated ${data.generated}`
          ),
          data.source ? h('div', { class: 'sub mono' }, data.source) : null
        ),
        themeBtn
      ),
      data.failure.length
        ? h('div', { class: 'failure mono' }, data.failure.join('\n'))
        : null
    )
  }

  const tiles = () => {
    const byPath = {}
    for (const c of data.conns) byPath[c.path] = (byPath[c.path] ?? 0) + 1
    const errors = data.marks.filter((m) => m.kind === 'error').length
    const tile = (k, v, d) =>
      h(
        'div',
        { class: 'tile' },
        h('div', { class: 'k' }, k),
        h('div', { class: 'v' }, v),
        d ? h('div', { class: 'd' }, d) : null
      )
    const reached = data.peers
      .map((p) => {
        const plan = data.planned[p]
        if (!plan) return null
        if (scriptEnd[p]?.event === 'script.done')
          return `${p} ${plan.length}/${plan.length}`
        return `${p} stopped in step ${lastStep[p]?.index ?? 0} of ${plan.length}`
      })
      .filter(Boolean)
    return h(
      'div',
      { class: 'tiles' },
      tile('Duration', secs(data.duration)),
      tile('Peers', String(data.peers.length), data.peers.join(' ')),
      tile(
        'Connections opened',
        String(data.conns.length),
        Object.entries(byPath)
          .map(([p, n]) => `${p} ${n}`)
          .join(' · ') || 'none'
      ),
      tile(
        'Errors in traces',
        String(errors),
        errors ? 'see the timeline and the table' : null
      ),
      tile('Events', String(data.events.length)),
      reached.length
        ? tile(
            'Script steps',
            data.peers.every(
              (p) => !data.planned[p] || scriptEnd[p]?.event === 'script.done'
            )
              ? 'all finished'
              : 'stopped early',
            reached.join(' · ')
          )
        : null
    )
  }

  // ---- network diagram ----
  const diagram = () => {
    const holder = h('div', {})
    const side = h('div', { class: 'side' })
    const card = h(
      'section',
      { class: 'card' },
      h(
        'div',
        { class: 'card-head' },
        h(
          'div',
          {},
          h('h2', {}, 'Network'),
          h(
            'div',
            { class: 'sub' },
            'Hover the timeline to see the network at that moment. Click it to pin.'
          )
        ),
        h(
          'div',
          { class: 'legend' },
          ...PATHS.map((p) =>
            h(
              'span',
              {},
              h('span', { class: 'sw', style: `background:${pathColor(p)}` }),
              p
            )
          ),
          h(
            'span',
            {},
            h('span', { class: 'sw line', style: 'background:var(--axis)' }),
            'lab link'
          )
        )
      ),
      h('div', { class: 'diagram-wrap' }, holder, side)
    )
    const topo = data.topology
    const draw = () => {
      holder.innerHTML = ''
      const w = Math.max(360, holder.clientWidth || 800)
      const lab = topo.layer === 2
      const n = data.peers.length
      const height = lab ? (topo.nat && topo.nat !== 'none' ? 360 : 320) : 280
      const s = svg(
        'svg',
        { width: w, height, role: 'img', 'aria-label': 'Network diagram' },
        holder
      )
      const t = cursorT()
      const px = (i) => (w / (n + 1)) * (i + 1)
      const peerY = lab ? height - 110 : height - 120
      const pos = {}
      data.peers.forEach((p, i) => {
        pos[p] = { x: px(i), y: peerY }
      })
      const dht = { x: w / 2, y: 34 }
      const router = { x: w / 2, y: lab ? 112 : 0 }
      const hasNat = lab && topo.nat && topo.nat !== 'none'
      const gwY = (router.y + peerY) / 2 + 6

      // Infrastructure.
      const line = (a, b, cls = 'axis') =>
        svg('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: cls }, s)
      if (lab) {
        line(dht, router)
        for (const p of data.peers) {
          if (hasNat) {
            line(router, { x: pos[p].x, y: gwY })
            line({ x: pos[p].x, y: gwY }, pos[p])
          } else line(router, pos[p])
        }
      } else {
        for (const p of data.peers) line(dht, pos[p])
      }

      // Peer-to-peer connections, one curve per pair of peers.
      const pairs = new Map()
      for (const c of data.conns) {
        const other = c.remotePeer
        if (!other || !pos[other]) continue
        const key = [c.peer, other].sort().join('|')
        if (!pairs.has(key)) pairs.set(key, [])
        pairs.get(key).push(c)
      }
      let pairIndex = 0
      for (const [key, conns] of pairs) {
        const [a, b] = key.split('|')
        const active = t === null ? conns : conns.filter((c) => isOpenAt(c, t))
        const shown = active.length ? active : conns
        const counts = {}
        for (const c of shown) counts[c.path] = (counts[c.path] ?? 0) + 1
        const mainPath = Object.entries(counts).sort(
          (x, y) => y[1] - x[1]
        )[0][0]
        const pa = pos[a]
        const pb = pos[b]
        const dip = 40 + 34 * (pairIndex++ % 3)
        const mx = (pa.x + pb.x) / 2
        const my = Math.max(pa.y, pb.y) + dip
        const d = `M ${pa.x} ${pa.y + 16} Q ${mx} ${my} ${pb.x} ${pb.y + 16}`
        const faded = t !== null && !active.length
        const stroke = svg(
          'path',
          {
            d,
            fill: 'none',
            stroke: pathColor(mainPath),
            'stroke-width': faded ? 1.5 : 2.5,
            'stroke-opacity': faded ? 0.25 : 1,
            'stroke-dasharray': faded ? '4 4' : null
          },
          s
        )
        const hit = svg(
          'path',
          { d, fill: 'none', stroke: 'transparent', 'stroke-width': 14 },
          s
        )
        const labels = [...new Set(shown.map((c) => c.label))]
        const opened = conns.filter((c) => c.peer === a).length
        const text =
          t === null
            ? `${opened} connection${opened === 1 ? '' : 's'}: ${labels.join(', ')}`
            : active.length
              ? `open: ${labels.join(', ')}`
              : 'not connected'
        // The curve's lowest point, with the label just under it.
        const labelY = 0.25 * (pa.y + 16) + 0.5 * my + 0.25 * (pb.y + 16) + 14
        svg(
          'text',
          {
            x: mx,
            y: labelY,
            'text-anchor': 'middle',
            class: faded ? 'muted-ink' : 'ink'
          },
          s
        ).textContent = text
        hit.addEventListener('mousemove', (evt) => {
          const lines = conns.map(
            (c) =>
              `${c.peer}→${peerOf(c)} ${c.label} ${c.path} ${plus(c.open)}–${c.close === null ? 'end' : plus(c.close)}  ${bytes(c.bytesRead)} in`
          )
          showTip(
            tipHtml(
              `${a} ↔ ${b}: ${conns.length} connection events (both sides)`,
              lines
                .slice(0, 16)
                .concat(
                  lines.length > 16 ? [`… ${lines.length - 16} more`] : []
                )
            ),
            evt
          )
        })
        hit.addEventListener('mouseleave', hideTip)
        void stroke
      }

      // Nodes.
      const box = (x, y, label, sub, opts = {}) => {
        const g = svg('g', {}, s)
        const wBox = opts.w ?? 108
        svg(
          'rect',
          {
            x: x - wBox / 2,
            y: y - 16,
            width: wBox,
            height: 32,
            rx: 6,
            fill: 'var(--surface-1)',
            stroke: opts.stroke ?? 'var(--axis)',
            'stroke-width': opts.strokeWidth ?? 1.5,
            'stroke-dasharray': opts.dash ?? null
          },
          g
        )
        svg(
          'text',
          {
            x,
            y: sub ? y - 2 : y + 4,
            'text-anchor': 'middle',
            class: 'ink',
            'font-weight': 600
          },
          g
        ).textContent = label
        if (sub)
          svg(
            'text',
            { x, y: y + 11, 'text-anchor': 'middle', 'font-size': 10 },
            g
          ).textContent = sub
        return g
      }
      if (lab) {
        box(
          dht.x,
          dht.y,
          'DHT bootstrap',
          topo.bootstrap ? `${topo.bootstrap} · ${topo.dhtNodes} nodes` : null,
          { w: 190 }
        )
        if (topo.relay)
          box(dht.x + 200, dht.y, 'blind relay', 'dht namespace', { w: 120 })
        const routerSub = [
          topo.blockUdp ? 'drops peer↔peer UDP' : null,
          `${topo.linkDelay || '5ms'} per link`
        ]
          .filter(Boolean)
          .join(' · ')
        box(router.x, router.y, 'router', routerSub, {
          w: topo.blockUdp ? 250 : 170
        })
        if (hasNat)
          for (const p of data.peers)
            box(pos[p].x, gwY, `gw${p}`, `NAT ${topo.nat}`, { w: 96 })
        const fault = [
          topo.netem ? `netem ${topo.netem}` : null,
          topo.bandwidth ? `rate ${topo.bandwidth}` : null
        ]
          .filter(Boolean)
          .join(' · ')
        if (fault)
          svg(
            'text',
            { x: 8, y: peerY - 34, class: 'muted-ink' },
            s
          ).textContent = `peer links: ${fault}`
      } else {
        const boot = Array.isArray(topo.bootstrap)
          ? topo.bootstrap.map((b) => `${b.host}:${b.port}`).join(', ')
          : ''
        box(
          dht.x,
          dht.y,
          'testnet DHT',
          boot ? `loopback ${boot}` : 'loopback',
          { w: 200 }
        )
      }
      for (const p of data.peers) {
        const exit = data.exits[p]
        const band = t !== null ? bandAt(p, t) : null
        const killedAt = data.marks.find(
          (m) => m.kind === 'kill' && m.peer === p
        )
        const killed =
          t !== null &&
          killedAt &&
          killedAt.t <= t &&
          !data.marks.some(
            (m) =>
              m.kind === 'resume' &&
              m.peer === p &&
              m.t <= t &&
              m.t > killedAt.t
          )
        const bad = exit !== undefined && exit !== 0
        const sub = killed
          ? 'killed'
          : band
            ? band.kind
            : exit !== undefined
              ? `exit ${exit}`
              : null
        box(pos[p].x, pos[p].y, `peer ${p}`, sub, {
          w: 96,
          stroke: bad || killed ? 'var(--critical)' : 'var(--text-secondary)',
          strokeWidth: bad || killed ? 2 : 1.5,
          dash: band || killed ? '4 3' : null
        })
      }

      // Side panel: what the cursor shows.
      side.innerHTML = ''
      const dl = h('dl', {})
      dl.append(
        h('dt', {}, 'Time'),
        h(
          'dd',
          { class: 'cursor-read' },
          t === null
            ? 'whole run (hover the timeline)'
            : `${plus(t)} s${state.pinned !== null && state.cursor === null ? ' (pinned)' : ''}`
        )
      )
      if (t !== null) {
        const open = data.conns.filter((c) => isOpenAt(c, t))
        dl.append(
          h(
            'dt',
            {},
            `Open connections (${open.length}, counted on each side)`
          ),
          h(
            'dd',
            {},
            open.length
              ? h(
                  'div',
                  { class: 'mono' },
                  ...open.map((c) =>
                    h('div', {}, `${c.peer}→${peerOf(c)} ${c.label} ${c.path}`)
                  )
                )
              : 'none'
          )
        )
        const steps = data.peers.map((p) => {
          const last = [...data.steps]
            .reverse()
            .find(
              (st) => st.peer === p && st.t <= t && st.event === 'script.step'
            )
          return last
            ? `${p}: step ${last.index} ${last.op}${last.f.name ? ` ${last.f.name}` : last.f.key ? ` ${last.f.key}` : ''}`
            : null
        })
        if (steps.some(Boolean))
          dl.append(
            h('dt', {}, 'Running step'),
            h(
              'dd',
              { class: 'mono' },
              ...steps.filter(Boolean).map((x) => h('div', {}, x))
            )
          )
      } else if (topo.layer === 2) {
        dl.append(
          h('dt', {}, 'Lab'),
          h(
            'dd',
            { class: 'mono' },
            h(
              'div',
              {},
              `nat=${topo.nat || 'none'} relay=${topo.relay ? 1 : 0} block_udp=${topo.blockUdp ? 1 : 0}`
            ),
            topo.netem ? h('div', {}, `netem ${topo.netem}`) : null,
            topo.bandwidth ? h('div', {}, `bandwidth ${topo.bandwidth}`) : null,
            topo.kill ? h('div', {}, `kill ${topo.kill}`) : null,
            topo.partition ? h('div', {}, `partition ${topo.partition}`) : null
          )
        )
      }
      side.append(dl)
    }
    redrawers.push(draw)
    cursorers.push(draw)
    return card
  }

  // ---- shared x scale for timeline charts ----
  const LEFT = 132
  const RIGHT = 16
  const xScale = (width) => {
    const span = state.to - state.from
    const k = (width - LEFT - RIGHT) / span
    return {
      x: (t) => LEFT + (t - state.from) * k,
      t: (x) => state.from + (x - LEFT) / k,
      k
    }
  }
  const drawAxis = (s, sc, width, top, bottom) => {
    const step = niceStep(
      state.to - state.from,
      Math.max(4, Math.floor((width - LEFT) / 90))
    )
    const first = Math.ceil(state.from / step) * step
    for (let v = first; v <= state.to; v += step) {
      const x = sc.x(v)
      svg('line', { x1: x, x2: x, y1: top, y2: bottom, class: 'grid' }, s)
      svg(
        'text',
        { x, y: top - 4, 'text-anchor': 'middle', class: 'muted-ink' },
        s
      ).textContent = `${(v / 1000).toFixed(step < 1000 ? 1 : 0)} s`
    }
  }
  const attachCursor = (s, sc, width, onCursorDraw) => {
    let dragFrom = null
    let dragRect = null
    const local = (evt) => evt.clientX - s.getBoundingClientRect().left
    s.addEventListener('mousedown', (evt) => {
      const x = local(evt)
      if (x < LEFT) return
      dragFrom = x
    })
    s.addEventListener('mousemove', (evt) => {
      const x = local(evt)
      if (dragFrom !== null && Math.abs(x - dragFrom) > 4) {
        if (!dragRect)
          dragRect = svg(
            'rect',
            {
              y: 0,
              height: s.getAttribute('height'),
              fill: 'var(--wash)',
              stroke: 'var(--axis)'
            },
            s
          )
        dragRect.setAttribute('x', Math.min(x, dragFrom))
        dragRect.setAttribute('width', Math.abs(x - dragFrom))
        return
      }
      if (x < LEFT || x > width - RIGHT) {
        if (state.cursor !== null) {
          state.cursor = null
          moveCursor()
        }
        return
      }
      state.cursor = Math.max(0, Math.min(end, sc.t(x)))
      moveCursor()
    })
    s.addEventListener('mouseleave', () => {
      dragFrom = null
      if (dragRect) dragRect.remove()
      dragRect = null
      state.cursor = null
      moveCursor()
    })
    s.addEventListener('mouseup', (evt) => {
      const x = local(evt)
      if (dragFrom !== null && dragRect) {
        const a = sc.t(Math.min(x, dragFrom))
        const b = sc.t(Math.max(x, dragFrom))
        dragRect.remove()
        dragRect = null
        dragFrom = null
        if (b - a > 1) {
          state.from = Math.max(0, a)
          state.to = Math.min(end, b)
          redraw()
        }
        return
      }
      dragFrom = null
      if (x >= LEFT) {
        const t = sc.t(x)
        state.pinned =
          state.pinned !== null && Math.abs(sc.x(state.pinned) - x) < 4
            ? null
            : t
        moveCursor()
      }
    })
    s.addEventListener('dblclick', () => {
      state.from = 0
      state.to = end
      redraw()
    })
    const cursorLine = svg(
      'line',
      {
        y1: 14,
        y2: s.getAttribute('height'),
        stroke: 'var(--text-secondary)',
        'stroke-width': 1,
        visibility: 'hidden',
        'pointer-events': 'none'
      },
      s
    )
    const pinLine = svg(
      'line',
      {
        y1: 14,
        y2: s.getAttribute('height'),
        stroke: 'var(--series-1)',
        'stroke-width': 1.5,
        visibility: 'hidden',
        'pointer-events': 'none'
      },
      s
    )
    const readout = svg(
      'text',
      {
        y: 11,
        'text-anchor': 'middle',
        class: 'ink',
        visibility: 'hidden',
        'pointer-events': 'none',
        style: 'paint-order:stroke;stroke:var(--surface-1);stroke-width:5px'
      },
      s
    )
    const place = () => {
      const show = (node, t) => {
        if (t === null || t < state.from || t > state.to)
          node.setAttribute('visibility', 'hidden')
        else {
          node.setAttribute('visibility', 'visible')
          node.setAttribute('x1', sc.x(t))
          node.setAttribute('x2', sc.x(t))
        }
      }
      show(cursorLine, state.cursor)
      show(pinLine, state.pinned)
      const t = cursorT()
      if (t === null || t < state.from || t > state.to)
        readout.setAttribute('visibility', 'hidden')
      else {
        readout.setAttribute('visibility', 'visible')
        readout.setAttribute(
          'x',
          Math.min(width - 40, Math.max(LEFT + 30, sc.x(t)))
        )
        readout.textContent = `${plus(t)} s`
      }
      onCursorDraw?.(t)
    }
    place()
    return place
  }

  // ---- timeline lanes ----
  const lanes = () => {
    const holder = h('div', {})
    const resetBtn = h(
      'button',
      {
        onclick: () => {
          state.from = 0
          state.to = end
          redraw()
        }
      },
      'Reset zoom'
    )
    const card = h(
      'section',
      { class: 'card' },
      h(
        'div',
        { class: 'card-head' },
        h(
          'div',
          {},
          h('h2', {}, 'Timeline'),
          h(
            'div',
            { class: 'sub' },
            'One group per peer. Drag to zoom, double-click to reset, click to pin a moment.'
          )
        ),
        h(
          'div',
          { class: 'legend' },
          ...PATHS.map((p) =>
            h(
              'span',
              {},
              h('span', { class: 'sw', style: `background:${pathColor(p)}` }),
              `${p} connection`
            )
          ),
          h(
            'span',
            {},
            h('span', { class: 'sw hatch' }),
            'offline / suspended'
          ),
          h('span', {}, h('span', { class: 'sw hatch crit' }), 'partitioned'),
          h(
            'span',
            {},
            h('span', { class: 'glyph', style: 'color:var(--critical)' }, '!'),
            'error'
          ),
          h(
            'span',
            {},
            h('span', { class: 'glyph', style: 'color:var(--critical)' }, '✕'),
            'killed'
          ),
          h('span', {}, h('span', { class: 'glyph' }, '◆'), 'epoch status'),
          resetBtn
        )
      ),
      holder
    )

    // Rows: per peer a heading, its script steps, then one row per swarm label and remote.
    const rows = []
    for (const p of data.peers) {
      rows.push({ type: 'head', peer: p })
      rows.push({ type: 'steps', peer: p })
      const keys = new Map()
      for (const c of data.conns.filter((c) => c.peer === p)) {
        const k = `${c.label}|${peerOf(c)}`
        if (!keys.has(k))
          keys.set(k, {
            type: 'conn',
            peer: p,
            label: c.label,
            remote: peerOf(c)
          })
      }
      const sorted = [...keys.values()].sort(
        (a, b) =>
          data.labels.indexOf(a.label) - data.labels.indexOf(b.label) ||
          a.remote.localeCompare(b.remote)
      )
      rows.push(...sorted)
      if (!sorted.length)
        rows.push({ type: 'conn', peer: p, label: null, remote: null })
    }
    const ROW = { head: 22, steps: 24, conn: 18 }
    const TOP = 22

    const draw = () => {
      holder.innerHTML = ''
      const width = Math.max(480, holder.clientWidth || 900)
      let y = TOP
      const placed = rows.map((r) => {
        const out = { ...r, y, hgt: ROW[r.type] }
        y += ROW[r.type]
        return out
      })
      const height = y + 8
      const s = svg(
        'svg',
        { width, height, role: 'img', 'aria-label': 'Timeline of every peer' },
        holder
      )
      const defs = svg('defs', {}, s)
      const pat = (id, color, op) => {
        const p = svg(
          'pattern',
          {
            id,
            width: 6,
            height: 6,
            patternUnits: 'userSpaceOnUse',
            patternTransform: 'rotate(45)'
          },
          defs
        )
        svg('rect', { width: 2, height: 6, fill: color, 'fill-opacity': op }, p)
      }
      pat('hatch', 'var(--text-secondary)', 0.35)
      pat('hatch-crit', 'var(--critical)', 0.45)
      const clip = svg('clipPath', { id: 'plot-clip' }, defs)
      svg('rect', { x: LEFT, y: 0, width: width - LEFT - RIGHT, height }, clip)
      svg('rect', { x: 0, y: 0, width, height, fill: 'transparent' }, s)
      const sc = xScale(width)
      drawAxis(s, sc, width, TOP - 4, height - 6)
      const plot = svg('g', { 'clip-path': 'url(#plot-clip)' }, s)
      const groupSpan = (peer) => {
        const mine = placed.filter((r) => r.peer === peer)
        return { y0: mine[0].y + ROW.head, y1: mine.at(-1).y + mine.at(-1).hgt }
      }
      const clampX = (t) => sc.x(Math.max(state.from, Math.min(state.to, t)))

      // Peer-wide bands first, behind everything.
      for (const b of data.bands.filter((b) => !b.label)) {
        const { y0, y1 } = groupSpan(b.peer)
        const x0 = clampX(b.from)
        const x1 = clampX(b.to ?? end)
        if (x1 <= x0) continue
        const r = svg(
          'rect',
          {
            x: x0,
            y: y0,
            width: x1 - x0,
            height: y1 - y0,
            fill: b.kind === 'partition' ? 'url(#hatch-crit)' : 'url(#hatch)'
          },
          plot
        )
        r.addEventListener('mousemove', (evt) =>
          showTip(
            tipHtml(`peer ${b.peer} ${b.kind}`, [
              `${plus(b.from)} → ${b.to === null ? 'end' : plus(b.to)}  (${secs((b.to ?? end) - b.from)})`
            ]),
            evt
          )
        )
        r.addEventListener('mouseleave', hideTip)
      }

      for (const r of placed) {
        if (r.type === 'head') {
          const exit = data.exits[r.peer]
          const exitText =
            exit === undefined ? '' : exit === 0 ? '  exit 0' : `  exit ${exit}`
          svg(
            'line',
            {
              x1: 0,
              x2: width - RIGHT,
              y1: r.y + 4,
              y2: r.y + 4,
              class: 'axis'
            },
            s
          )
          const tx = svg(
            'text',
            {
              x: 4,
              y: r.y + 17,
              class: 'ink',
              'font-weight': 600,
              'font-size': 12
            },
            s
          )
          tx.textContent = `peer ${r.peer}${exitText}`
          if (exit) tx.setAttribute('fill', 'var(--critical)')
          continue
        }
        if (r.type === 'steps') {
          svg('text', { x: 14, y: r.y + 15 }, s).textContent = 'script'
          const mine = data.steps.filter((st) => st.peer === r.peer)
          const scripted = mine.filter((st) => st.event === 'script.step')
          const finish = scriptEnd[r.peer]?.t ?? null
          const lastT = Math.max(
            ...data.events.filter((e) => e.peer === r.peer).map((e) => e.t)
          )
          if (scripted.length) {
            scripted.forEach((st, k) => {
              const next = scripted[k + 1]?.t ?? finish ?? lastT
              const x0 = clampX(st.t)
              const x1 = clampX(next)
              const wid = Math.max(1, x1 - x0 - 1)
              const running =
                k === scripted.length - 1 &&
                scriptEnd[r.peer]?.event !== 'script.done'
              const rect = svg(
                'rect',
                {
                  x: x0,
                  y: r.y + 5,
                  width: wid,
                  height: 14,
                  rx: 3,
                  fill: running ? 'var(--critical)' : 'var(--text-secondary)',
                  'fill-opacity': running ? 0.35 : k % 2 ? 0.18 : 0.3
                },
                plot
              )
              const name = `${st.op}${st.f.name ? ` ${st.f.name}` : st.f.key ? ` ${st.f.key}` : ''}`
              if (wid > name.length * 6 + 6) {
                const tx = svg(
                  'text',
                  {
                    x: x0 + 4,
                    y: r.y + 16,
                    class: 'ink',
                    'font-size': 10,
                    'pointer-events': 'none'
                  },
                  plot
                )
                tx.textContent = name
              }
              rect.addEventListener('mousemove', (evt) =>
                showTip(
                  tipHtml(
                    `peer ${r.peer} step ${st.index}: ${name}`,
                    [
                      `${plus(st.t)} → ${plus(next)}  (${secs(next - st.t)})`,
                      running ? 'still running when the trace ended' : '',
                      fieldsText(st.f)
                    ].filter(Boolean)
                  ),
                  evt
                )
              )
              rect.addEventListener('mouseleave', hideTip)
            })
          } else {
            for (const st of mine) {
              const x = sc.x(st.t)
              if (st.t < state.from || st.t > state.to) continue
              svg(
                'line',
                {
                  x1: x,
                  x2: x,
                  y1: r.y + 4,
                  y2: r.y + 20,
                  stroke: 'var(--text-secondary)',
                  'stroke-width': 2
                },
                plot
              )
              const hit = svg(
                'rect',
                {
                  x: x - 5,
                  y: r.y + 2,
                  width: 10,
                  height: 20,
                  fill: 'transparent'
                },
                plot
              )
              hit.addEventListener('mousemove', (evt) =>
                showTip(
                  tipHtml(`peer ${r.peer} ${st.event}`, [
                    plus(st.t),
                    fieldsText(st.f)
                  ]),
                  evt
                )
              )
              hit.addEventListener('mouseleave', hideTip)
            }
            // Label steps where they don't collide.
            let lastX = -Infinity
            for (const st of mine) {
              if (st.t < state.from || st.t > state.to) continue
              const x = sc.x(st.t)
              const text = st.event.replace(/^peer\./, '')
              if (x - lastX < text.length * 6 + 10) continue
              svg(
                'text',
                {
                  x: x + 4,
                  y: r.y + 15,
                  class: 'ink',
                  'font-size': 10,
                  'pointer-events': 'none'
                },
                plot
              ).textContent = text
              lastX = x
            }
          }
          for (const m of data.marks.filter(
            (m) => m.peer === r.peer && m.kind === 'epoch'
          )) {
            if (m.t < state.from || m.t > state.to) continue
            const x = sc.x(m.t)
            const d = svg(
              'path',
              {
                d: `M ${x} ${r.y + 6} l 5 6 l -5 6 l -5 -6 z`,
                fill: 'var(--text-primary)',
                stroke: 'var(--surface-1)',
                'stroke-width': 1.5
              },
              plot
            )
            d.addEventListener('mousemove', (evt) =>
              showTip(
                tipHtml(`peer ${r.peer} epoch status`, [
                  plus(m.t),
                  m.text,
                  fieldsText(data.events[m.i].f)
                ]),
                evt
              )
            )
            d.addEventListener('mouseleave', hideTip)
          }
          continue
        }
        // Connection row.
        svg('text', { x: 14, y: r.y + 13 }, s).textContent = r.label
          ? `${r.label} ↔ ${r.remote}`
          : 'no connections'
        svg(
          'line',
          {
            x1: LEFT,
            x2: width - RIGHT,
            y1: r.y + r.hgt,
            y2: r.y + r.hgt,
            class: 'grid'
          },
          s
        )
        for (const b of data.bands.filter(
          (b) => b.label && b.peer === r.peer && b.label === r.label
        )) {
          const x0 = clampX(b.from)
          const x1 = clampX(b.to ?? end)
          if (x1 > x0)
            svg(
              'rect',
              {
                x: x0,
                y: r.y + 1,
                width: x1 - x0,
                height: r.hgt - 2,
                fill: 'url(#hatch)'
              },
              plot
            )
        }
        for (const c of data.conns.filter(
          (c) =>
            c.peer === r.peer && c.label === r.label && peerOf(c) === r.remote
        )) {
          const x0 = clampX(c.open)
          const x1 = clampX(c.close ?? end)
          if (c.open > state.to || (c.close ?? end) < state.from) continue
          const bar = svg(
            'rect',
            {
              x: x0,
              y: r.y + 4,
              width: Math.max(2, x1 - x0 - 2),
              height: 10,
              rx: 3,
              fill: pathColor(c.path)
            },
            plot
          )
          if (x1 - x0 > 70) {
            svg(
              'text',
              {
                x: x0 + 5,
                y: r.y + 12.5,
                fill: '#fff',
                'font-size': 9.5,
                'pointer-events': 'none',
                style: 'fill:#fff'
              },
              plot
            ).textContent = `${c.path}${c.initiator ? ' · out' : ' · in'}`
          }
          bar.addEventListener('mousemove', (evt) =>
            showTip(
              tipHtml(`${c.peer} → ${peerOf(c)} on ${c.label}: ${c.path}`, [
                `open ${plus(c.open)}  close ${c.close === null ? 'still open at end' : plus(c.close)}  (${secs((c.close ?? end) - c.open)})${c.endedBy ? `  ended by the ${c.endedBy === 'kill' ? 'kill' : 'process restart'}, no close traced` : ''}`,
                `${c.initiator ? 'outgoing (this peer dialled)' : 'incoming'}  remote ${c.remoteAddress ?? '?'}  key ${c.remote}`,
                `read ${bytes(c.bytesRead)}  written ${bytes(c.bytesWritten)}`
              ]),
              evt
            )
          )
          bar.addEventListener('mouseleave', hideTip)
        }
        for (const m of data.marks.filter(
          (m) =>
            m.kind === 'error' &&
            m.peer === r.peer &&
            m.label === r.label &&
            r.label
        )) {
          if (m.t < state.from || m.t > state.to) continue
          drawError(plot, sc.x(m.t), r.y + 9, m)
        }
      }
      // Errors without a swarm label go on the script row.
      for (const m of data.marks.filter(
        (m) =>
          m.kind === 'error' && (!m.label || !data.labels.includes(m.label))
      )) {
        const row = placed.find((r) => r.type === 'steps' && r.peer === m.peer)
        if (row && m.t >= state.from && m.t <= state.to)
          drawError(plot, sc.x(m.t), row.y + 12, m)
      }
      // Kills and restarts span the peer's group.
      for (const m of data.marks.filter(
        (m) => m.kind === 'kill' || m.kind === 'resume'
      )) {
        if (m.t < state.from || m.t > state.to) continue
        const { y0, y1 } = groupSpan(m.peer)
        const x = sc.x(m.t)
        const crit = m.kind === 'kill'
        svg(
          'line',
          {
            x1: x,
            x2: x,
            y1: y0,
            y2: y1,
            stroke: crit ? 'var(--critical)' : 'var(--text-secondary)',
            'stroke-width': 2
          },
          plot
        )
        const nearEnd = x > width - RIGHT - 90
        svg(
          'text',
          {
            x: nearEnd ? x - 4 : x + 4,
            y: y0 - 6,
            'text-anchor': nearEnd ? 'end' : 'start',
            class: 'ink',
            'font-weight': 600,
            style: crit ? 'fill:var(--critical)' : null
          },
          plot
        ).textContent = crit ? '✕ killed' : '↻ restarted'
      }
      // Where a failed run stopped.
      if (data.failed && end <= state.to) {
        const x = sc.x(end)
        svg(
          'line',
          {
            x1: x,
            x2: x,
            y1: TOP - 4,
            y2: height - 6,
            stroke: 'var(--critical)',
            'stroke-width': 1.5
          },
          s
        )
        svg(
          'text',
          {
            x: x - 4,
            y: TOP + 10,
            'text-anchor': 'end',
            style: 'fill:var(--critical)',
            'font-weight': 600
          },
          s
        ).textContent = 'run ended (failed)'
      }
      const place = attachCursor(s, sc, width)
      cursorers.push(place)
      // Keep only the newest cursor painter for this chart.
      if (draw.place) cursorers.splice(cursorers.indexOf(draw.place), 1)
      draw.place = place
    }
    const drawError = (parent, x, y, m) => {
      const g = svg('g', {}, parent)
      svg(
        'circle',
        {
          cx: x,
          cy: y,
          r: 6,
          fill: 'var(--critical)',
          stroke: 'var(--surface-1)',
          'stroke-width': 2
        },
        g
      )
      svg(
        'text',
        {
          x,
          y: y + 3.5,
          'text-anchor': 'middle',
          'font-size': 10,
          'font-weight': 700,
          style: 'fill:#fff',
          'pointer-events': 'none'
        },
        g
      ).textContent = '!'
      svg('circle', { cx: x, cy: y, r: 10, fill: 'transparent' }, g)
      g.addEventListener('mousemove', (evt) =>
        showTip(
          tipHtml(`peer ${m.peer} error`, [
            plus(m.t),
            m.text,
            fieldsText(data.events[m.i]?.f ?? {})
          ]),
          evt
        )
      )
      g.addEventListener('mouseleave', hideTip)
    }
    redrawers.push(draw)
    return card
  }

  // ---- autobase progress, small multiples ----
  const progress = () => {
    const ORDER = ['vault', 'master']
    const rank = (l) => (ORDER.includes(l) ? ORDER.indexOf(l) : ORDER.length)
    const labels = [...new Set(data.progress.map((p) => p.label))].sort(
      (a, b) => rank(a) - rank(b)
    )
    if (!labels.length) return null
    const holder = h('div', {})
    const card = h(
      'section',
      { class: 'card' },
      h(
        'div',
        { class: 'card-head' },
        h(
          'div',
          {},
          h('h2', {}, 'Autobase progress'),
          h(
            'div',
            { class: 'sub' },
            'Per peer and vault: blocks known (length), signed by the indexers, and indexed. A peer whose indexed line stops short of the others has stopped indexing.'
          )
        ),
        h(
          'div',
          { class: 'legend' },
          ...PROGRESS_SERIES.map(([, name, color]) =>
            h(
              'span',
              {},
              h('span', { class: 'sw line', style: `background:${color}` }),
              name
            )
          )
        )
      ),
      holder
    )
    const draw = () => {
      holder.innerHTML = ''
      const width = Math.max(480, holder.clientWidth || 900)
      const PH = 96
      const GAP = 30
      const rowsOut = []
      for (const label of labels) {
        for (const peer of data.peers) {
          const pts = data.progress.filter(
            (p) => p.label === label && p.peer === peer
          )
          if (pts.length) rowsOut.push({ label, peer, pts })
        }
      }
      const height = 22 + rowsOut.length * (PH + GAP)
      const s = svg(
        'svg',
        {
          width,
          height,
          role: 'img',
          'aria-label': 'Autobase lengths over time'
        },
        holder
      )
      const defs = svg('defs', {}, s)
      const clip = svg('clipPath', { id: 'prog-clip' }, defs)
      svg('rect', { x: LEFT, y: 0, width: width - LEFT - RIGHT, height }, clip)
      svg('rect', { x: 0, y: 0, width, height, fill: 'transparent' }, s)
      const sc = xScale(width)
      drawAxis(s, sc, width, 18, height - GAP + 8)
      const maxByLabel = {}
      for (const r of rowsOut)
        maxByLabel[r.label] = Math.max(
          maxByLabel[r.label] ?? 1,
          ...r.pts.map((p) => p.length)
        )
      const panels = []
      rowsOut.forEach((r, k) => {
        const top = 22 + k * (PH + GAP)
        const max = maxByLabel[r.label]
        const yv = (v) => top + PH - (v / max) * PH
        svg(
          'line',
          {
            x1: LEFT,
            x2: width - RIGHT,
            y1: top + PH,
            y2: top + PH,
            class: 'axis'
          },
          s
        )
        svg(
          'line',
          { x1: LEFT, x2: width - RIGHT, y1: top, y2: top, class: 'grid' },
          s
        )
        svg(
          'text',
          { x: LEFT - 6, y: top + 4, 'text-anchor': 'end', class: 'muted-ink' },
          s
        ).textContent = String(max)
        svg(
          'text',
          {
            x: LEFT - 6,
            y: top + PH,
            'text-anchor': 'end',
            class: 'muted-ink'
          },
          s
        ).textContent = '0'
        svg(
          'text',
          { x: 4, y: top + 14, class: 'ink', 'font-weight': 600 },
          s
        ).textContent = `peer ${r.peer}`
        svg('text', { x: 4, y: top + 28 }, s).textContent = r.label
        const last = r.pts.at(-1)
        svg('text', { x: 4, y: top + 46, 'font-size': 10 }, s).textContent =
          `len ${last.length}`
        svg('text', { x: 4, y: top + 58, 'font-size': 10 }, s).textContent =
          `signed ${last.signedLength}`
        svg('text', { x: 4, y: top + 70, 'font-size': 10 }, s).textContent =
          `indexed ${last.indexedLength}`
        const g = svg('g', { 'clip-path': 'url(#prog-clip)' }, s)
        for (const [field, , color] of PROGRESS_SERIES) {
          let d = ''
          r.pts.forEach((p, i) => {
            const x = sc.x(p.t)
            const y = yv(p[field])
            d += i === 0 ? `M ${x} ${y}` : ` H ${x} V ${y}`
          })
          d += ` H ${sc.x(end)}`
          svg(
            'path',
            {
              d,
              fill: 'none',
              stroke: color,
              'stroke-width': 2,
              'stroke-linejoin': 'round'
            },
            g
          )
        }
        panels.push({ ...r, top, yv })
      })
      const dots = svg('g', { 'pointer-events': 'none' }, s)
      const place = attachCursor(s, sc, width, (t) => {
        dots.innerHTML = ''
        if (t === null) return
        for (const p of panels) {
          const at = [...p.pts].reverse().find((pt) => pt.t <= t)
          if (!at) continue
          for (const [field, , color] of PROGRESS_SERIES) {
            svg(
              'circle',
              {
                cx: sc.x(t),
                cy: p.yv(at[field]),
                r: 4,
                fill: color,
                stroke: 'var(--surface-1)',
                'stroke-width': 2
              },
              dots
            )
          }
          svg(
            'text',
            {
              x: Math.min(width - 150, sc.x(t) + 8),
              y: p.top + 12,
              class: 'ink',
              'font-size': 10
            },
            dots
          ).textContent =
            `len ${at.length} · signed ${at.signedLength} · indexed ${at.indexedLength}`
        }
      })
      cursorers.push(place)
      if (draw.place) cursorers.splice(cursorers.indexOf(draw.place), 1)
      draw.place = place
    }
    redrawers.push(draw)
    return card
  }

  // ---- script plan vs what ran ----
  const plan = () => {
    const peers = data.peers.filter((p) => data.planned[p])
    if (!peers.length) return null
    return h(
      'section',
      { class: 'card' },
      h(
        'div',
        { class: 'card-head' },
        h(
          'div',
          {},
          h('h2', {}, 'Scenario steps'),
          h(
            'div',
            { class: 'sub' },
            'What each peer was asked to do, and how far it got.'
          )
        )
      ),
      h(
        'div',
        { class: 'steps-grid' },
        ...peers.map((p) => {
          const done = scriptEnd[p]?.event === 'script.done'
          const at = lastStep[p]?.index ?? -1
          return h(
            'div',
            {},
            h(
              'strong',
              {},
              `peer ${p}`,
              data.exits[p] !== undefined
                ? h('span', { class: 'muted' }, `  exit ${data.exits[p]}`)
                : null
            ),
            h(
              'ol',
              { class: 'plan mono' },
              ...data.planned[p].map((st, i) =>
                h(
                  'li',
                  {
                    class:
                      done || i < at ? 'done' : i === at ? 'current' : 'todo',
                    value: i
                  },
                  `${i}  ${st.text}`
                )
              )
            )
          )
        })
      )
    )
  }

  // ---- event table ----
  const table = () => {
    const body = h('tbody', {})
    const count = h('span', { class: 'muted' })
    const search = h('input', {
      type: 'search',
      placeholder: 'Filter: event, label, key, code…',
      oninput: (e) => {
        state.text = e.target.value.toLowerCase()
        fill()
      }
    })
    const fam = h(
      'select',
      {
        onchange: (e) => {
          state.family = e.target.value
          fill()
        }
      },
      ...[
        'all',
        'connections',
        'steps',
        'errors',
        'vault',
        'autobase',
        'network'
      ].map((f) => h('option', { value: f }, f))
    )
    const peerButtons = data.peers.map((p) => {
      const b = h(
        'button',
        {
          'aria-pressed': 'true',
          onclick: () => {
            if (state.peers.has(p)) state.peers.delete(p)
            else state.peers.add(p)
            b.setAttribute('aria-pressed', String(state.peers.has(p)))
            fill()
          }
        },
        p
      )
      return b
    })
    const rangeBox = h('input', {
      type: 'checkbox',
      checked: true,
      onchange: (e) => {
        state.inRange = e.target.checked
        fill()
      }
    })
    const LIMIT = 2000
    const fill = () => {
      body.innerHTML = ''
      const rows = data.events.filter(
        (e) =>
          state.peers.has(e.peer) &&
          (state.family === 'all' || family(e.event) === state.family) &&
          (!state.inRange || (e.t >= state.from && e.t <= state.to)) &&
          (!state.text ||
            `${e.event} ${JSON.stringify(e.f)}`
              .toLowerCase()
              .includes(state.text))
      )
      count.textContent = `${rows.length} of ${data.events.length} events${rows.length > LIMIT ? `, first ${LIMIT} shown` : ''}`
      const frag = document.createDocumentFragment()
      for (const e of rows.slice(0, LIMIT)) {
        const tr = h(
          'tr',
          {
            class: `row${family(e.event) === 'errors' ? ' err' : ''}${state.pinned === e.t ? ' pinned' : ''}`,
            onclick: () => {
              state.pinned = e.t
              if (e.t < state.from || e.t > state.to) {
                state.from = 0
                state.to = end
                redraw()
              } else moveCursor()
              for (const other of body.querySelectorAll('tr.pinned'))
                other.classList.remove('pinned')
              tr.classList.add('pinned')
            }
          },
          h('td', { class: 'num' }, plus(e.t)),
          h('td', {}, e.peer),
          h('td', {}, e.event),
          h('td', { class: 'fields' }, fieldsText(e.f))
        )
        frag.appendChild(tr)
      }
      body.appendChild(frag)
    }
    redrawers.push(fill)
    return h(
      'section',
      { class: 'card' },
      h(
        'div',
        { class: 'card-head' },
        h(
          'div',
          {},
          h('h2', {}, 'Events'),
          h(
            'div',
            { class: 'sub' },
            'Every traced event. Click a row to pin its moment in the charts.'
          )
        )
      ),
      h(
        'div',
        { class: 'toolbar' },
        search,
        fam,
        h('span', { class: 'muted' }, 'peers'),
        ...peerButtons,
        h('label', {}, rangeBox, ' only the zoomed range'),
        h('span', { class: 'spacer' }),
        count
      ),
      h(
        'div',
        { class: 'table-wrap' },
        h(
          'table',
          {},
          h(
            'thead',
            {},
            h(
              'tr',
              {},
              h('th', {}, 's'),
              h('th', {}, 'peer'),
              h('th', {}, 'event'),
              h('th', {}, 'fields')
            )
          ),
          body
        )
      )
    )
  }

  const logs = () => {
    const parts = []
    if (data.logs.assert)
      parts.push(
        h(
          'details',
          { open: data.failed },
          h('summary', {}, 'Assertions (assert.mjs output)'),
          h('pre', {}, data.logs.assert)
        )
      )
    if (data.logs.lab)
      parts.push(
        h(
          'details',
          {},
          h('summary', {}, 'Lab log'),
          h('pre', {}, data.logs.lab)
        )
      )
    if (!parts.length) return null
    return h('section', { class: 'card' }, h('h2', {}, 'Logs'), ...parts)
  }

  app.append(
    header(),
    tiles(),
    diagram(),
    lanes(),
    progress() ?? '',
    plan() ?? '',
    table(),
    logs() ?? ''
  )
  redraw()
  // Redraw on width changes only; height changes come from our own redraws.
  let lastWidth = app.clientWidth
  let pending = null
  new ResizeObserver(() => {
    if (pending || app.clientWidth === lastWidth) return
    pending = window.requestAnimationFrame(() => {
      pending = null
      lastWidth = app.clientWidth
      redraw()
    })
  }).observe(app)
}
