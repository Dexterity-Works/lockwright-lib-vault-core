/* global document, window, requestAnimationFrame, cancelAnimationFrame */
// The report page. Runs from file:// with no network. Every trace value is
// untrusted text and reaches the page only through textContent and
// setAttribute, never as markup.
;(() => {
  const data = JSON.parse(document.getElementById('report-data').textContent)
  const SVGNS = 'http://www.w3.org/2000/svg'
  const app = document.getElementById('app')
  const { devices, events } = data
  const span = Math.max(events.length ? events[events.length - 1].w : 0, 1)

  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag)
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue
      if (key === 'text') node.textContent = String(value)
      else if (key === 'on') {
        for (const [name, fn] of Object.entries(value)) {
          node.addEventListener(name, fn)
        }
      } else node.setAttribute(key, String(value))
    }
    for (const child of children) {
      if (child === null || child === undefined) continue
      node.append(
        typeof child === 'string' ? document.createTextNode(child) : child
      )
    }
    return node
  }
  const sv = (tag, attrs = {}, text) => {
    const node = document.createElementNS(SVGNS, tag)
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined) continue
      node.setAttribute(key, String(value))
    }
    if (text !== undefined) node.textContent = String(text)
    return node
  }

  const secs = (ms) => `+${(ms / 1000).toFixed(3)}s`
  const wallOf = (e) =>
    data.t0 ? new Date(Date.parse(data.t0) + e.w).toISOString() : ''
  const fieldsText = (f) => {
    try {
      return JSON.stringify(f)
    } catch {
      return '?'
    }
  }
  const describe = (e) =>
    [
      `${secs(e.w)}  ${devices[e.d]?.name ?? '?'}  ${e.e}${e.l ? ` [${e.l}]` : ''}`,
      wallOf(e),
      fieldsText(e.f)
    ].join('\n')

  // ---- derived structures ---------------------------------------------------

  const owner = new Map()
  for (const e of events) {
    if (e.e === 'swarm.create' && typeof e.f.key === 'string')
      owner.set(e.f.key, e.d)
  }

  /** Connection intervals per device: conn.open to the matching conn.close. */
  const conns = []
  {
    const openByKey = new Map()
    for (const e of events) {
      if (e.e !== 'conn.open' && e.e !== 'conn.close' && e.e !== 'conn.upgrade')
        continue
      const key = `${e.d}|${e.l}|${e.f.remote}`
      if (e.e === 'conn.open') {
        const c = {
          d: e.d,
          label: e.l,
          remote: e.f.remote,
          start: e.w,
          end: null,
          path: e.f.path ?? 'unknown',
          paths: [{ w: e.w, path: e.f.path ?? 'unknown' }],
          open: e,
          close: null
        }
        conns.push(c)
        if (!openByKey.has(key)) openByKey.set(key, [])
        openByKey.get(key).push(c)
      } else {
        const list = openByKey.get(key)
        if (!list || !list.length) continue
        if (e.e === 'conn.upgrade') {
          const c = list[list.length - 1]
          c.paths.push({ w: e.w, path: e.f.path ?? 'unknown' })
        } else {
          const c = list.shift()
          c.end = e.w
          c.close = e
        }
      }
    }
  }
  const pathAt = (c, w) => {
    let path = c.paths[0].path
    for (const p of c.paths) if (p.w <= w) path = p.path
    return path
  }

  /** Faults drawn as bands across every row. */
  const bands = []
  {
    const pairs = [
      ['peer.offline', 'peer.online', 'offline'],
      ['peer.closeVault', 'peer.openVault', 'vault closed'],
      ['fault.start', 'fault.end', null]
    ]
    for (const [from, to, what] of pairs) {
      const openAt = new Map()
      for (const e of events) {
        const key = `${e.d}|${e.f.name ?? ''}`
        if (e.e === from) openAt.set(key, e)
        else if (e.e === to && openAt.has(key)) {
          const s = openAt.get(key)
          openAt.delete(key)
          bands.push({
            start: s.w,
            end: e.w,
            text: `${devices[e.d]?.name ?? '?'} ${what ?? String(s.f.name ?? 'fault')}`
          })
        }
      }
      for (const s of openAt.values()) {
        bands.push({
          start: s.w,
          end: span,
          text: `${devices[s.d]?.name ?? '?'} ${what ?? String(s.f.name ?? 'fault')}`
        })
      }
    }
  }

  const SAMPLES = new Set(['swarm.stats', 'dht.stats', 'swarm.peers'])
  const kindOf = (e) => {
    const n = e.e
    if (SAMPLES.has(n)) return null
    if (n === 'conn.open' || n === 'conn.close' || n === 'conn.upgrade')
      return null
    if (n === 'conn.attempt') return 'attempt'
    if (n === 'conn.fail' || n === 'peer.ban') return 'fail'
    if (n === 'epoch.status') return 'epoch'
    if (n.startsWith('migration.')) return 'migration'
    if (n === 'error') return 'error'
    if (/^(peer|soak|fault|personal)\./.test(n)) return 'step'
    if (/^(pairing|epoch|writer|device)\./.test(n)) return 'pairing'
    return 'other'
  }

  // ---- state ----------------------------------------------------------------

  // The cursor starts where teardown starts, so the diagram shows the
  // network as the test left it rather than as the peers shut down.
  const teardown = events.find((e) => e.e === 'peer.stop')
  const state = {
    v0: 0,
    v1: span,
    cursor: teardown ? teardown.w : span,
    selected: null,
    matched: null,
    matchedName: null
  }
  const listeners = []
  const changed = (what) => {
    for (const fn of listeners) fn(what)
  }

  // ---- tooltip ----------------------------------------------------------------

  const tip = el('div', { id: 'tip', role: 'tooltip' })
  document.body.append(tip)
  const showTip = (text, x, y) => {
    tip.textContent = text
    tip.style.display = 'block'
    const w = tip.offsetWidth
    const h = tip.offsetHeight
    tip.style.left = `${Math.min(x + 14, window.innerWidth - w - 8)}px`
    tip.style.top = `${Math.min(y + 14, window.innerHeight - h - 8)}px`
  }
  const hideTip = () => {
    tip.style.display = 'none'
  }

  // ---- theme ------------------------------------------------------------------

  document.getElementById('theme')?.addEventListener('click', () => {
    const root = document.documentElement
    const dark =
      root.dataset.theme === 'dark' ||
      (!root.dataset.theme &&
        window.matchMedia?.('(prefers-color-scheme: dark)').matches)
    root.dataset.theme = dark ? 'light' : 'dark'
  })

  // ---- summary, devices, clocks ----------------------------------------------

  const summary = document.getElementById('summary')
  if (summary && data.t0) {
    summary.textContent = `${events.length} events from ${devices.length} device(s), ${secs(span)} from ${data.t0}`
  }

  const devicesSection = () => {
    const rows = devices.map((d) =>
      el(
        'tr',
        {},
        el('td', { text: d.name }),
        el('td', { text: d.files.join(', ') || '-' }),
        el('td', { class: 'num', text: d.count }),
        el('td', { class: 'num', text: d.first ?? '-' }),
        el('td', { class: 'num', text: d.last ?? '-' })
      )
    )
    const skew = data.skew.length
      ? el(
          'ul',
          {},
          ...data.skew.map((s) =>
            el('li', {
              text: `${devices[s.b]?.name} clock minus ${devices[s.a]?.name}: ${s.ms >= 0 ? '+' : ''}${s.ms} ms (median of ${s.n} connection(s), ${s.min} to ${s.max} ms)`
            })
          )
        )
      : el('p', {
          class: 'hint',
          text: 'No connection was seen from both ends, so the clock offset between devices is unknown.'
        })
    return el(
      'section',
      { 'aria-labelledby': 'h-devices' },
      el('h2', { id: 'h-devices', text: 'Devices and clocks' }),
      el(
        'table',
        {},
        el(
          'thead',
          {},
          el(
            'tr',
            {},
            ...['Device', 'Files', 'Events', 'First (wall)', 'Last (wall)'].map(
              (h) => el('th', { text: h })
            )
          )
        ),
        el('tbody', {}, ...rows)
      ),
      el(
        'p',
        { class: 'hint' },
        'Events are placed by each device’s own wall clock and are not corrected. The offsets below come from both ends of the same connection and include network latency.'
      ),
      skew,
      ...data.warnings.map((w) => el('p', { class: 'warn', text: w }))
    )
  }

  // ---- assertions -----------------------------------------------------------

  const assertsSection = () => {
    const list = Array.isArray(data.asserts)
      ? data.asserts
      : Array.isArray(data.asserts?.asserts)
        ? data.asserts.asserts
        : null
    if (!list) return null
    const byKey = new Map(
      events.map((e) => [`${devices[e.d]?.name}|${e.e}|${wallOf(e)}`, e.i])
    )
    const matchedOf = (a) =>
      new Set(
        (Array.isArray(a?.matched) ? a.matched : [])
          .map((m) =>
            typeof m === 'number'
              ? m
              : byKey.get(`${m?.peer}|${m?.event}|${m?.wall}`)
          )
          .filter((i) => typeof i === 'number')
      )
    const rows = list.map((a) => {
      const pass = a?.pass ?? a?.ok ?? a?.status === 'pass'
      const matched = matchedOf(a)
      return el(
        'tr',
        {},
        el('td', { text: a?.name ?? a?.label ?? '?' }),
        el('td', {
          class: pass ? 'pass' : 'failed',
          text: pass ? 'pass' : 'fail'
        }),
        el('td', { text: a?.message ?? '' }),
        el(
          'td',
          {},
          matched.size
            ? el('button', {
                type: 'button',
                text: `${matched.size} event(s)`,
                on: {
                  click: () => {
                    state.matched = matched
                    state.matchedName = String(a?.name ?? '?')
                    changed('filter')
                  }
                }
              })
            : '-'
        )
      )
    })
    return el(
      'section',
      { 'aria-labelledby': 'h-asserts' },
      el('h2', { id: 'h-asserts', text: 'Assertions' }),
      el(
        'table',
        {},
        el(
          'thead',
          {},
          el(
            'tr',
            {},
            ...['Assertion', 'Result', 'Message', 'Matched'].map((h) =>
              el('th', { text: h })
            )
          )
        ),
        el('tbody', {}, ...rows)
      )
    )
  }

  // ---- network diagram ------------------------------------------------------

  const PATH_COLOR = {
    direct: 'var(--direct)',
    holepunched: 'var(--holepunched)',
    relayed: 'var(--relayed)'
  }
  const pathColor = (p) => PATH_COLOR[p] ?? 'var(--other)'

  const diagram = () => {
    const W = 640
    const H = 380
    const cx = W / 2
    const cy = H / 2 - 6
    const nodes = new Map()
    const addNode = (id, label, kind) => {
      if (!nodes.has(id)) nodes.set(id, { id, label: String(label), kind })
      return nodes.get(id)
    }
    devices.forEach((d, i) => addNode(`d:${i}`, d.name, 'device'))
    const deviceByName = new Map(devices.map((d, i) => [d.name, `d:${i}`]))
    const topo =
      data.topology && typeof data.topology === 'object' ? data.topology : null
    const topoId = (id) => deviceByName.get(String(id)) ?? `t:${id}`
    if (Array.isArray(topo?.nodes)) {
      for (const n of topo.nodes) {
        const id = topoId(n?.id)
        if (!id.startsWith('d:'))
          addNode(id, n?.label ?? n?.id ?? '?', n?.kind ?? 'node')
      }
    }
    // With no topology, the DHT bootstrap nodes the devices were given.
    const dhtLinks = new Map()
    if (!Array.isArray(topo?.nodes)) {
      for (const e of events) {
        if (e.e !== 'dht.create' || !Array.isArray(e.f.bootstrap)) continue
        for (const b of e.f.bootstrap) {
          const addr = typeof b === 'string' ? b : `${b?.host}:${b?.port}`
          const id = `b:${addr}`
          addNode(id, `DHT ${addr}`, 'dht')
          const key = `d:${e.d}|${id}`
          if (!dhtLinks.has(key))
            dhtLinks.set(key, { a: `d:${e.d}`, b: id, w: null })
        }
      }
      for (const e of events) {
        if (e.e !== 'dht.ready') continue
        for (const link of dhtLinks.values()) {
          if (link.a === `d:${e.d}` && (link.w === null || e.w < link.w))
            link.w = e.w
        }
      }
    }
    const remoteNode = (remote) => {
      const d = owner.get(remote)
      if (d !== undefined) return `d:${d}`
      const id = `k:${remote}`
      const unknown = [...nodes.values()].filter(
        (n) => n.kind === 'unknown'
      ).length
      if (!nodes.has(id) && unknown >= 16) return null
      return addNode(id, `peer ${remote}`, 'unknown').id
    }
    for (const e of events) {
      if (
        (e.e === 'conn.open' ||
          e.e === 'conn.attempt' ||
          e.e === 'conn.fail') &&
        e.f.remote
      ) {
        remoteNode(String(e.f.remote))
      }
    }

    // Layout: devices on a ring, DHT and lab nodes in the middle, peers no
    // device owns on an outer ring.
    const list = [...nodes.values()]
    const ring = (items, r, offset = -Math.PI / 2) =>
      items.forEach((n, i) => {
        const a = offset + (2 * Math.PI * i) / Math.max(items.length, 1)
        n.x = cx + r * Math.cos(a)
        n.y = cy + r * Math.sin(a)
      })
    const devs = list.filter((n) => n.kind === 'device')
    const middle = list.filter(
      (n) => n.kind !== 'device' && n.kind !== 'unknown'
    )
    const outer = list.filter((n) => n.kind === 'unknown')
    ring(devs, 130)
    if (middle.length === 1) {
      middle[0].x = cx
      middle[0].y = cy
    } else ring(middle, Math.min(60, 18 * middle.length), 0)
    ring(outer, 178, -Math.PI / 2 + Math.PI / Math.max(outer.length, 1))

    const svg = sv('svg', {
      viewBox: `0 0 ${W} ${H}`,
      role: 'img',
      'aria-label': 'Network diagram at the cursor time'
    })
    const linkLayer = sv('g')
    const nodeLayer = sv('g')
    svg.append(linkLayer, nodeLayer)
    for (const n of list) {
      const g = sv('g', { tabindex: 0 })
      if (n.kind === 'device') {
        g.append(
          sv('circle', {
            cx: n.x,
            cy: n.y,
            r: 16,
            fill: 'var(--surface)',
            stroke: 'var(--ink)',
            'stroke-width': 2
          })
        )
      } else if (n.kind === 'unknown') {
        g.append(
          sv('circle', {
            cx: n.x,
            cy: n.y,
            r: 8,
            fill: 'var(--surface)',
            stroke: 'var(--muted)',
            'stroke-width': 1.5,
            'stroke-dasharray': '3 2'
          })
        )
      } else {
        g.append(
          sv('rect', {
            x: n.x - 9,
            y: n.y - 9,
            width: 18,
            height: 18,
            rx: 3,
            fill: 'var(--surface)',
            stroke: 'var(--ink-2)',
            'stroke-width': 1.5
          })
        )
      }
      g.append(
        sv(
          'text',
          {
            x: n.x,
            y: n.y + (n.kind === 'device' ? 31 : 22),
            'text-anchor': 'middle',
            class: n.kind === 'device' ? 'ink' : 'muted'
          },
          n.label
        )
      )
      g.addEventListener('mousemove', (ev) =>
        showTip(n.label, ev.clientX, ev.clientY)
      )
      g.addEventListener('mouseleave', hideTip)
      nodeLayer.append(g)
    }

    const pairKey = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`)
    // Along the link and kept upright, so labels of links that meet at a
    // node do not overlap.
    const linkLabel = (a, b, text, cls) => {
      let angle = (Math.atan2(b.y - a.y, b.x - a.x) * 180) / Math.PI
      if (angle > 90) angle -= 180
      if (angle < -90) angle += 180
      const mx = (a.x + b.x) / 2
      const my = (a.y + b.y) / 2
      return sv(
        'text',
        {
          x: mx,
          y: my - 5,
          'text-anchor': 'middle',
          class: cls,
          transform: `rotate(${angle.toFixed(1)} ${mx} ${my})`
        },
        text
      )
    }
    const draw = () => {
      linkLayer.replaceChildren()
      const T = state.cursor
      const links = new Map()
      const link = (a, b) => {
        const key = pairKey(a, b)
        if (!links.has(key)) {
          links.set(key, {
            a,
            b,
            open: [],
            closed: 0,
            fails: [],
            attempts: 0,
            lastOpenAt: -1
          })
        }
        return links.get(key)
      }
      for (const c of conns) {
        const other = remoteNode(String(c.remote))
        if (!other || c.start > T) continue
        const l = link(`d:${c.d}`, other)
        if (c.end === null || c.end > T) l.open.push({ c, path: pathAt(c, T) })
        else l.closed++
        l.lastOpenAt = Math.max(l.lastOpenAt, c.end ?? c.start)
      }
      for (const e of events) {
        if (e.w > T) break
        if (e.e !== 'conn.attempt' && e.e !== 'conn.fail') continue
        const other = e.f.remote ? remoteNode(String(e.f.remote)) : null
        if (!other) continue
        const l = link(`d:${e.d}`, other)
        if (e.e === 'conn.attempt') l.attempts++
        else l.fails.push(e)
      }
      for (const l of dhtLinks.values()) {
        if (l.w === null || l.w > T) continue
        const a = nodes.get(l.a)
        const b = nodes.get(l.b)
        linkLayer.append(
          sv('line', {
            x1: a.x,
            y1: a.y,
            x2: b.x,
            y2: b.y,
            stroke: 'var(--axis)',
            'stroke-width': 1
          })
        )
      }
      if (Array.isArray(topo?.links)) {
        for (const t of topo.links) {
          const a = nodes.get(topoId(t?.from ?? t?.source))
          const b = nodes.get(topoId(t?.to ?? t?.target))
          if (!a || !b) continue
          linkLayer.append(
            sv('line', {
              x1: a.x,
              y1: a.y,
              x2: b.x,
              y2: b.y,
              stroke: 'var(--axis)',
              'stroke-width': 1.5
            })
          )
          if (t?.label) linkLayer.append(linkLabel(a, b, t.label, 'muted'))
        }
      }
      const drops = new Map()
      for (const r of data.net ?? []) {
        if (!r || r.drops === undefined) continue
        const at = Date.parse(r.wall)
        if (data.t0 && !Number.isNaN(at) && at - Date.parse(data.t0) > T)
          continue
        const a = deviceByName.get(String(r.from)) ?? `t:${r.from}`
        const b = deviceByName.get(String(r.to)) ?? `t:${r.to}`
        drops.set(pairKey(a, b), r.drops)
      }
      for (const l of links.values()) {
        const a = nodes.get(l.a)
        const b = nodes.get(l.b)
        if (!a || !b) continue
        const failing =
          !l.open.length && l.fails.some((f) => f.w > l.lastOpenAt)
        const paths = [...new Set(l.open.map((o) => o.path))]
        const color = l.open.length
          ? pathColor(paths[paths.length - 1])
          : failing
            ? 'var(--critical)'
            : 'var(--muted)'
        const line = sv('line', {
          x1: a.x,
          y1: a.y,
          x2: b.x,
          y2: b.y,
          stroke: color,
          'stroke-width': l.open.length ? 3 : 2,
          'stroke-dasharray': l.open.length ? null : failing ? '6 4' : '2 4',
          'stroke-linecap': 'round',
          opacity: l.open.length || failing ? 1 : 0.6
        })
        const text = l.open.length
          ? `${paths.join('+')}${l.open.length > 1 ? ` ×${l.open.length}` : ''}`
          : failing
            ? `failing (${l.fails[l.fails.length - 1].f.code ?? '?'})`
            : 'closed'
        const drop = drops.get(pairKey(l.a, l.b))
        const details = [
          `${a.label} ↔ ${b.label} at ${secs(T)}`,
          ...l.open.map(
            (o) =>
              `open [${o.c.label}] ${o.path} from ${devices[o.c.d]?.name} since ${secs(o.c.start)}`
          ),
          `${l.closed} closed, ${l.attempts} attempt(s), ${l.fails.length} failed`,
          ...l.fails
            .slice(-5)
            .map(
              (f) =>
                `fail ${secs(f.w)} ${devices[f.d]?.name} [${f.l}] ${f.f.code ?? '?'} after ${f.f.ms ?? '?'} ms`
            ),
          drop !== undefined ? `drops ${JSON.stringify(drop)}` : null
        ].filter(Boolean)
        const hit = sv('line', {
          x1: a.x,
          y1: a.y,
          x2: b.x,
          y2: b.y,
          stroke: 'transparent',
          'stroke-width': 14
        })
        const g = sv('g')
        g.append(line, hit)
        g.append(
          linkLabel(
            a,
            b,
            drop !== undefined ? `${text}, drops ${drop}` : text,
            failing ? 'ink' : ''
          )
        )
        g.addEventListener('mousemove', (ev) =>
          showTip(details.join('\n'), ev.clientX, ev.clientY)
        )
        g.addEventListener('mouseleave', hideTip)
        linkLayer.append(g)
      }
    }
    listeners.push((what) => {
      if (what === 'cursor' || what === 'all') draw()
    })
    draw()

    const slider = el('input', {
      type: 'range',
      min: 0,
      max: span,
      step: 1,
      value: state.cursor,
      'aria-label': 'Cursor time',
      on: {
        input: (ev) => {
          state.cursor = Number(ev.target.value)
          changed('cursor')
        }
      }
    })
    const at = el('span', { class: 'num', text: secs(state.cursor) })
    let playing = null
    const play = el('button', {
      type: 'button',
      text: 'Play',
      on: {
        click: () => {
          if (playing) {
            cancelAnimationFrame(playing)
            playing = null
            play.textContent = 'Play'
            return
          }
          play.textContent = 'Pause'
          const from = state.cursor >= span ? 0 : state.cursor
          const started = performanceNow()
          const duration = 8000
          const step = () => {
            const k = Math.min((performanceNow() - started) / duration, 1)
            state.cursor = from + (span - from) * k
            changed('cursor')
            if (k < 1) playing = requestAnimationFrame(step)
            else {
              playing = null
              play.textContent = 'Play'
            }
          }
          playing = requestAnimationFrame(step)
        }
      }
    })
    listeners.push((what) => {
      if (what !== 'cursor' && what !== 'all') return
      slider.value = String(Math.round(state.cursor))
      at.textContent = secs(state.cursor)
    })
    return el(
      'section',
      { 'aria-labelledby': 'h-net' },
      el('h2', { id: 'h-net', text: 'Network' }),
      el('div', { class: 'row' }, play, slider, at),
      svg,
      el(
        'div',
        { class: 'legend' },
        el('span', { style: '--c: var(--direct)', text: 'direct' }),
        el('span', { style: '--c: var(--holepunched)', text: 'holepunched' }),
        el('span', { style: '--c: var(--relayed)', text: 'relayed' }),
        el('span', {
          class: 'dash',
          style: '--c: var(--critical)',
          text: 'failing attempts'
        }),
        el('span', {
          class: 'dash',
          style: '--c: var(--muted)',
          text: 'closed'
        })
      ),
      el('p', {
        class: 'hint',
        text: 'Connections open at the cursor time. Drag the slider, press Play, or click the timeline.'
      })
    )
  }
  const performanceNow = () =>
    window.performance ? window.performance.now() : Date.now()

  // ---- timeline -------------------------------------------------------------

  const timeline = () => {
    const wrap = el('div', { id: 'timeline-wrap' })
    const G = 120
    // Tick labels, then one strip per fault label row, then the rows.
    const TICKS = 22
    const STRIP = 13 * Math.min(bands.length, 3)
    const AXIS = TICKS + STRIP + 6
    const rowsMeta = devices.map((d, i) => {
      const keys = [
        ...new Set(
          conns.filter((c) => c.d === i).map((c) => `${c.label}|${c.remote}`)
        )
      ]
      return { keys, sub: Math.max(keys.length, 1) }
    })
    const TRACK = { step: 18, attempt: 14, state: 14 }
    let svg = null
    const render = () => {
      const width = Math.max(wrap.clientWidth || 900, 480)
      const plot = width - G - 12
      const { v0, v1 } = state
      const x = (w) => G + ((w - v0) / (v1 - v0)) * plot
      const visible = (w) =>
        w >= v0 - (v1 - v0) * 0.02 && w <= v1 + (v1 - v0) * 0.02
      let y = AXIS
      const layout = rowsMeta.map((m) => {
        const top = y
        const conn = top + TRACK.step
        const attempt = conn + m.sub * 8 + 4
        const st = attempt + TRACK.attempt
        y = st + TRACK.state + 10
        return { top, conn, attempt, state: st, bottom: y }
      })
      const height = Math.max(y, AXIS + 20)
      const next = sv('svg', {
        viewBox: `0 0 ${width} ${height}`,
        height,
        role: 'img',
        'aria-label': 'Per-device timeline'
      })

      // Axis.
      const range = v1 - v0
      const raw = range / 8
      const pow = 10 ** Math.floor(Math.log10(Math.max(raw, 0.001)))
      const stepMs =
        [1, 2, 5, 10].map((k) => k * pow).find((s) => s >= raw) ?? pow * 10
      for (let w = Math.ceil(v0 / stepMs) * stepMs; w <= v1; w += stepMs) {
        next.append(
          sv('line', {
            x1: x(w),
            x2: x(w),
            y1: TICKS - 4,
            y2: height,
            stroke: 'var(--grid)',
            'stroke-width': 1
          })
        )
        next.append(
          sv(
            'text',
            { x: x(w), y: TICKS - 8, 'text-anchor': 'middle' },
            stepMs < 1000
              ? `+${(w / 1000).toFixed(stepMs < 10 ? 3 : stepMs < 100 ? 2 : 1)}s`
              : `+${(w / 1000).toFixed(0)}s`
          )
        )
      }

      // Fault bands across all rows.
      bands.forEach((b, k) => {
        if (b.end < v0 || b.start > v1) return
        const x1 = Math.max(x(b.start), G)
        const x2 = Math.min(x(b.end), width - 12)
        const rect = sv('rect', {
          x: x1,
          y: AXIS,
          width: Math.max(x2 - x1, 2),
          height: height - AXIS,
          fill: 'var(--band)'
        })
        rect.addEventListener('mousemove', (ev) =>
          showTip(
            `${b.text}\n${secs(b.start)} to ${secs(b.end)}`,
            ev.clientX,
            ev.clientY
          )
        )
        rect.addEventListener('mouseleave', hideTip)
        next.append(rect)
        next.append(
          sv('rect', {
            x: x1,
            y: TICKS + (k % 3) * 13,
            width: Math.max(x2 - x1, 2),
            height: 12,
            fill: 'var(--band)'
          })
        )
        next.append(
          sv(
            'text',
            { x: x1 + 3, y: TICKS + 10 + (k % 3) * 13, class: 'ink' },
            b.text
          )
        )
      })

      // Rows.
      layout.forEach((r, i) => {
        next.append(
          sv('line', {
            x1: 0,
            x2: width,
            y1: r.bottom - 5,
            y2: r.bottom - 5,
            stroke: 'var(--grid)'
          })
        )
        next.append(
          sv(
            'text',
            { x: 8, y: r.top + 14, class: 'ink', 'font-weight': 600 },
            devices[i].name
          )
        )
        next.append(
          sv('text', { x: 8, y: r.conn + 8, class: 'muted' }, 'connections')
        )
        next.append(
          sv('text', { x: 8, y: r.attempt + 10, class: 'muted' }, 'attempts')
        )
        next.append(
          sv('text', { x: 8, y: r.state + 10, class: 'muted' }, 'epoch, sync')
        )
      })
      for (const c of conns) {
        const end = c.end ?? span
        if (end < v0 || c.start > v1) continue
        const r = layout[c.d]
        const sub = rowsMeta[c.d].keys.indexOf(`${c.label}|${c.remote}`)
        // One segment per path, so an upgrade shows where it happened.
        c.paths.forEach((p, k) => {
          const s = Math.max(p.w, v0)
          const e = Math.min(
            k + 1 < c.paths.length ? c.paths[k + 1].w : end,
            v1
          )
          if (e < s) return
          const rect = sv('rect', {
            x: x(s),
            y: r.conn + sub * 8,
            width: Math.max(x(e) - x(s), 2),
            height: 6,
            rx: 2,
            fill: pathColor(p.path),
            'data-i': c.open.i
          })
          next.append(rect)
        })
      }
      const lastLabel = new Map()
      for (const e of events) {
        if (!visible(e.w)) continue
        const kind = kindOf(e)
        if (!kind) continue
        const r = layout[e.d]
        const X = x(e.w)
        let mark
        if (kind === 'step') {
          mark = sv('rect', {
            x: X - 1,
            y: r.top + 2,
            width: 2,
            height: 12,
            fill: 'var(--ink-2)'
          })
          const last = lastLabel.get(e.d) ?? -Infinity
          if (X - last > 80) {
            next.append(
              sv(
                'text',
                { x: X + 3, y: r.top + 12, class: 'ink' },
                e.e.replace(/^peer\./, '')
              )
            )
            lastLabel.set(e.d, X)
          }
        } else if (kind === 'attempt') {
          mark = sv('circle', {
            cx: X,
            cy: r.attempt + 6,
            r: 3,
            fill: 'none',
            stroke: 'var(--ink-2)',
            'stroke-width': 1.2
          })
        } else if (kind === 'fail') {
          const yy = r.attempt + 6
          mark = sv('path', {
            d: `M${X - 4},${yy - 4}L${X + 4},${yy + 4}M${X - 4},${yy + 4}L${X + 4},${yy - 4}`,
            stroke: 'var(--critical)',
            'stroke-width': 2,
            'stroke-linecap': 'round'
          })
        } else if (kind === 'epoch') {
          const yy = r.state + 6
          const revoked = e.f.revoked === true
          mark = sv('path', {
            d: `M${X},${yy - 5}L${X + 5},${yy}L${X},${yy + 5}L${X - 5},${yy}Z`,
            fill: revoked
              ? 'var(--critical)'
              : e.f.canRead === false
                ? 'var(--surface)'
                : 'var(--epoch)',
            stroke: revoked ? 'var(--critical)' : 'var(--epoch)',
            'stroke-width': 1.5
          })
        } else if (kind === 'migration') {
          const yy = r.state + 6
          const color =
            e.e === 'migration.error'
              ? 'var(--critical)'
              : e.e === 'migration.deferred' || e.e === 'migration.skipped'
                ? 'var(--warning)'
                : 'var(--ink-2)'
          mark = sv('rect', {
            x: X - 4,
            y: yy - 4,
            width: 8,
            height: 8,
            rx: 1,
            fill: color
          })
        } else if (kind === 'pairing') {
          const yy = r.state + 6
          mark = sv('path', {
            d: `M${X},${yy - 5}L${X + 5},${yy + 4}L${X - 5},${yy + 4}Z`,
            fill: 'var(--ink)'
          })
        } else if (kind === 'error') {
          mark = sv('rect', {
            x: X - 3,
            y: r.state + 1,
            width: 6,
            height: 10,
            fill: 'var(--critical)'
          })
        } else {
          mark = sv('rect', {
            x: X - 0.5,
            y: r.state + 3,
            width: 1,
            height: 7,
            fill: 'var(--muted)'
          })
        }
        mark.setAttribute('data-i', String(e.i))
        next.append(mark)
      }
      if (state.selected !== null) {
        const e = events[state.selected]
        if (e && visible(e.w)) {
          const r = layout[e.d]
          next.append(
            sv('rect', {
              x: x(e.w) - 7,
              y: r.top,
              width: 14,
              height: r.bottom - r.top - 6,
              fill: 'none',
              stroke: 'var(--direct)',
              'stroke-width': 2,
              rx: 3
            })
          )
        }
      }
      if (state.cursor >= v0 && state.cursor <= v1) {
        next.append(
          sv('line', {
            x1: x(state.cursor),
            x2: x(state.cursor),
            y1: TICKS - 4,
            y2: height,
            stroke: 'var(--ink)',
            'stroke-width': 1,
            'stroke-dasharray': '4 3'
          })
        )
      }
      if (svg) svg.replaceWith(next)
      else wrap.append(next)
      svg = next
      windowText.textContent = `${secs(v0)} to ${secs(v1)}`
    }

    const timeAt = (clientX) => {
      const rect = wrap.getBoundingClientRect()
      const width = Math.max(wrap.clientWidth || 900, 480)
      const scale = rect.width / width || 1
      const px = (clientX - rect.left) / scale
      const plot = width - G - 12
      return state.v0 + ((px - G) / plot) * (state.v1 - state.v0)
    }
    const setWindow = (v0, v1) => {
      const min = 5
      let a = v0
      let b = v1
      if (b - a < min) {
        const mid = (a + b) / 2
        a = mid - min / 2
        b = mid + min / 2
      }
      const extra = span * 0.05
      if (a < -extra) {
        b += -extra - a
        a = -extra
      }
      if (b > span + extra) {
        a -= b - span - extra
        b = span + extra
      }
      state.v0 = Math.max(a, -extra)
      state.v1 = b
      changed('window')
    }
    const zoom = (factor, around) => {
      const c = around ?? (state.v0 + state.v1) / 2
      setWindow(c - (c - state.v0) * factor, c + (state.v1 - c) * factor)
    }
    wrap.addEventListener(
      'wheel',
      (ev) => {
        ev.preventDefault()
        if (ev.shiftKey || Math.abs(ev.deltaX) > Math.abs(ev.deltaY)) {
          const d = ((ev.deltaX || ev.deltaY) / 600) * (state.v1 - state.v0)
          setWindow(state.v0 + d, state.v1 + d)
        } else {
          zoom(ev.deltaY > 0 ? 1.25 : 0.8, timeAt(ev.clientX))
        }
      },
      { passive: false }
    )
    let drag = null
    wrap.addEventListener('pointerdown', (ev) => {
      drag = {
        x: ev.clientX,
        v0: state.v0,
        v1: state.v1,
        moved: false,
        target: ev.target
      }
      wrap.setPointerCapture?.(ev.pointerId)
    })
    wrap.addEventListener('pointermove', (ev) => {
      if (drag) {
        const dx = ev.clientX - drag.x
        if (Math.abs(dx) > 3) drag.moved = true
        if (drag.moved) {
          wrap.classList.add('dragging')
          const rect = wrap.getBoundingClientRect()
          const width = Math.max(wrap.clientWidth || 900, 480)
          const plot = (width - G - 12) * (rect.width / width || 1)
          const d = (-dx / plot) * (drag.v1 - drag.v0)
          setWindow(drag.v0 + d, drag.v1 + d)
          hideTip()
          return
        }
      }
      const i = ev.target?.getAttribute?.('data-i')
      if (i !== null && i !== undefined && events[Number(i)]) {
        showTip(describe(events[Number(i)]), ev.clientX, ev.clientY)
      } else hideTip()
    })
    wrap.addEventListener('pointerleave', hideTip)
    wrap.addEventListener('pointerup', (ev) => {
      wrap.classList.remove('dragging')
      const d = drag
      drag = null
      if (!d || d.moved) return
      const i = d.target?.getAttribute?.('data-i')
      if (i !== null && i !== undefined && events[Number(i)]) {
        state.selected = Number(i)
        state.cursor = events[state.selected].w
        changed('select')
      } else {
        state.cursor = Math.min(Math.max(timeAt(ev.clientX), 0), span)
        changed('cursor')
      }
    })
    wrap.addEventListener('dblclick', () => setWindow(0, span))

    const windowText = el('span', { class: 'num' })
    const button = (text, fn) =>
      el('button', { type: 'button', text, on: { click: fn } })
    listeners.push((what) => {
      if (['window', 'cursor', 'select', 'all'].includes(what)) render()
    })
    window.addEventListener('resize', () => render())
    const section = el(
      'section',
      { 'aria-labelledby': 'h-timeline' },
      el('h2', { id: 'h-timeline', text: 'Timeline' }),
      el(
        'div',
        { class: 'row' },
        button('Zoom in', () => zoom(0.5)),
        button('Zoom out', () => zoom(2)),
        button('Whole run', () => setWindow(0, span)),
        button('Zoom to the table range', () => {
          const r = tableRange()
          if (r) setWindow(r[0], r[1])
        }),
        windowText,
        el('span', {
          class: 'hint',
          text: 'Wheel zooms, drag or shift+wheel scrolls, double-click resets, click a mark to find it in the table.'
        })
      ),
      wrap,
      el(
        'div',
        { class: 'legend' },
        el('span', { class: 'dot', style: '--c: var(--ink-2)', text: 'step' }),
        el('span', {
          class: 'dot',
          style: '--c: var(--direct)',
          text: 'connection open (colour = path)'
        }),
        el('span', {
          class: 'dot',
          style: '--c: var(--ink-2)',
          text: '○ attempt'
        }),
        el('span', {
          class: 'dot',
          style: '--c: var(--critical)',
          text: '✕ failed attempt'
        }),
        el('span', {
          class: 'dot',
          style: '--c: var(--epoch)',
          text: '◆ epoch status (hollow: cannot read)'
        }),
        el('span', {
          class: 'dot',
          style: '--c: var(--warning)',
          text: '■ migration (yellow: deferred or skipped)'
        }),
        el('span', {
          class: 'dot',
          style: '--c: var(--ink)',
          text: '▲ pairing, kick, rotation'
        }),
        el('span', { class: 'dot', style: '--c: var(--band)', text: 'fault' })
      )
    )
    return { section, render }
  }

  // ---- event table ------------------------------------------------------------

  let tableRange = () => null
  const table = () => {
    const device = el(
      'select',
      { 'aria-label': 'Device' },
      el('option', { value: '', text: 'All devices' }),
      ...devices.map((d, i) => el('option', { value: i, text: d.name }))
    )
    const name = el('input', {
      type: 'search',
      placeholder: 'event, e.g. conn.fail, epoch',
      'aria-label': 'Event name',
      size: 24
    })
    const label = el('input', {
      type: 'search',
      placeholder: 'label, e.g. vault',
      'aria-label': 'Label',
      size: 12
    })
    const text = el('input', {
      type: 'search',
      placeholder: 'any field text',
      'aria-label': 'Field text',
      size: 16
    })
    const from = el('input', {
      type: 'number',
      step: 'any',
      placeholder: 'from s',
      'aria-label': 'From seconds',
      style: 'width: 7em'
    })
    const to = el('input', {
      type: 'number',
      step: 'any',
      placeholder: 'to s',
      'aria-label': 'To seconds',
      style: 'width: 7em'
    })
    const follow = el('input', {
      type: 'checkbox',
      'aria-label': 'Only the timeline window'
    })
    const samples = el('input', {
      type: 'checkbox',
      checked: 'checked',
      'aria-label': 'Show sampled counters'
    })
    const count = el('span', { class: 'hint' })
    const matchedNote = el('span', { class: 'hint' })
    const tbody = el('tbody')
    const LIMIT = 2000
    tableRange = () => {
      const a = from.value === '' ? null : Number(from.value) * 1000
      const b = to.value === '' ? null : Number(to.value) * 1000
      if (a === null && b === null) return null
      return [a ?? 0, b ?? span]
    }
    const rowOf = new Map()
    const render = () => {
      const d = device.value === '' ? null : Number(device.value)
      const names = name.value
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
      const lab = label.value.trim().toLowerCase()
      const txt = text.value.trim().toLowerCase()
      const range = follow.checked ? [state.v0, state.v1] : tableRange()
      const rows = []
      let n = 0
      rowOf.clear()
      for (const e of events) {
        if (d !== null && e.d !== d) continue
        if (names.length && !names.some((s) => e.e.toLowerCase().includes(s)))
          continue
        if (lab && !(e.l ?? '').toLowerCase().includes(lab)) continue
        if (range && (e.w < range[0] || e.w > range[1])) continue
        if (!samples.checked && SAMPLES.has(e.e)) continue
        if (state.matched && !state.matched.has(e.i)) continue
        const fields = fieldsText(e.f)
        if (txt && !fields.toLowerCase().includes(txt)) continue
        n++
        if (rows.length >= LIMIT) continue
        const tr = el(
          'tr',
          {
            class:
              [
                e.i === state.selected ? 'hit' : '',
                e.e === 'conn.fail' || e.e === 'error' ? 'fail' : ''
              ]
                .join(' ')
                .trim() || null,
            on: {
              click: () => {
                state.selected = e.i
                state.cursor = e.w
                if (e.w < state.v0 || e.w > state.v1) {
                  const half = (state.v1 - state.v0) / 2
                  state.v0 = e.w - half
                  state.v1 = e.w + half
                }
                changed('select')
              }
            }
          },
          el('td', { class: 'num', text: secs(e.w) }),
          el('td', { class: 'num', text: wallOf(e).slice(11, 23) }),
          el('td', { text: devices[e.d]?.name ?? '?' }),
          el('td', { class: 'ev', text: e.e }),
          el('td', { text: e.l ?? '' }),
          el('td', { class: 'fields', text: fields })
        )
        rowOf.set(e.i, tr)
        rows.push(tr)
      }
      tbody.replaceChildren(...rows)
      count.textContent =
        n > LIMIT
          ? `${n} of ${events.length} events match; showing the first ${LIMIT}`
          : `${n} of ${events.length} events`
      matchedNote.replaceChildren()
      if (state.matched) {
        matchedNote.append(
          `Only events matched by "${state.matchedName}". `,
          el('button', {
            type: 'button',
            text: 'Show all',
            on: {
              click: () => {
                state.matched = null
                changed('filter')
              }
            }
          })
        )
      }
    }
    for (const input of [
      device,
      name,
      label,
      text,
      from,
      to,
      follow,
      samples
    ]) {
      input.addEventListener('input', render)
    }
    listeners.push((what) => {
      if (
        what === 'filter' ||
        what === 'all' ||
        (what === 'window' && follow.checked)
      )
        render()
      if (what === 'select') {
        render()
        rowOf.get(state.selected)?.scrollIntoView?.({ block: 'nearest' })
      }
    })
    const field = (text, input) => el('label', {}, text, input)
    return el(
      'section',
      { 'aria-labelledby': 'h-events' },
      el('h2', { id: 'h-events', text: 'Events' }),
      el(
        'div',
        { class: 'row' },
        device,
        name,
        label,
        text,
        field('from', from),
        field('to', to),
        field('only the timeline window', follow),
        field('sampled counters', samples)
      ),
      el('div', { class: 'row' }, count, matchedNote),
      el(
        'div',
        { class: 'scroll' },
        el(
          'table',
          {},
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              ...['Time', 'Wall', 'Device', 'Event', 'Label', 'Fields'].map(
                (h) => el('th', { text: h })
              )
            )
          ),
          tbody
        )
      )
    )
  }

  const netSection = () => {
    if (!data.net) return null
    return el(
      'section',
      { 'aria-labelledby': 'h-netlog' },
      el('h2', {
        id: 'h-netlog',
        text: `Network records (${data.net.length})`
      }),
      el(
        'div',
        { class: 'scroll' },
        el(
          'table',
          {},
          el(
            'tbody',
            {},
            ...data.net
              .slice(0, 1000)
              .map((r) =>
                el('tr', {}, el('td', { class: 'fields', text: fieldsText(r) }))
              )
          )
        )
      )
    )
  }

  const tl = timeline()
  app.replaceChildren(
    ...[
      el('div', { class: 'grid2' }, diagram(), devicesSection()),
      assertsSection(),
      tl.section,
      table(),
      netSection()
    ].filter(Boolean)
  )
  changed('all')
  document.body.dataset.ready = 'true'
})()
