'use strict'
// Builds one self-contained report.html from sync traces: the harness's
// per-peer JSONL, or the traceFile of several real devices (one file per
// device). Inline CSS and JS, the data embedded, no network requests, so
// it opens from file://. The report holds only what the traces hold.
// Trace values are untrusted text: the page writes them with textContent
// and the embedded JSON escapes every character that could end the script.
const fs = require('fs')
const path = require('path')

const CLIENT = fs.readFileSync(path.join(__dirname, 'client.js'), 'utf8')
const STYLE = fs.readFileSync(path.join(__dirname, 'style.css'), 'utf8')

const escapeHtml = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[
        c
      ]
  )

/** JSON safe inside a <script> element. */
const embedJson = (value) =>
  JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/[\u2028\u2029]/g, (c) => (c === '\u2028' ? '\\u2028' : '\\u2029'))

/** `laptop.jsonl`, `laptop.jsonl.1` and `laptop.trace.jsonl` all name `laptop`. */
const deviceNameFromFile = (file) =>
  path
    .basename(file)
    .replace(/(\.\d+)$/, '')
    .replace(/\.(jsonl|json|ndjson|log)$/, '')
    .replace(/\.trace$/, '') || 'device'

const parseJsonl = (text) => {
  const events = []
  let skipped = 0
  for (const line of text.split('\n')) {
    if (!line.trim()) continue
    try {
      const value = JSON.parse(line)
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        events.push(value)
      } else skipped++
    } catch {
      skipped++
    }
  }
  return { events, skipped }
}

/**
 * One trace file: JSONL, or a timeline.json (`{ name, failure, events }`).
 * @param {string} file
 * @returns {{ name: string, file: string, events: object[], skipped: number, failure?: object | null, title?: string }}
 */
const loadTrace = (file) => {
  const text = fs.readFileSync(file, 'utf8')
  const name = deviceNameFromFile(file)
  if (file.endsWith('.json')) {
    const doc = JSON.parse(text)
    return {
      name,
      file,
      events: Array.isArray(doc.events) ? doc.events : [],
      skipped: 0,
      failure: doc.failure ?? null,
      title: typeof doc.name === 'string' ? doc.name : undefined
    }
  }
  return { name, file, ...parseJsonl(text) }
}

const loadJsonl = (file) =>
  file ? parseJsonl(fs.readFileSync(file, 'utf8')).events : null
const loadJson = (file) =>
  file ? JSON.parse(fs.readFileSync(file, 'utf8')) : null

const META = new Set(['t', 'wall', 'peer', 'event', 'label'])
const str = (value) =>
  value === null || value === undefined ? null : String(value)

const median = (values) => {
  const sorted = [...values].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2
}

/**
 * Clock offsets between devices, from both ends of the same connection:
 * B's conn.open minus A's for a connection between A's and B's swarm keys.
 * Pairs are taken closest first, each open once. It includes the one-way
 * latency, so it is an estimate, shown and never applied.
 */
const estimateSkew = (devices, events) => {
  const keysOf = devices.map(() => new Set())
  for (const e of events) {
    if (e.e === 'swarm.create' && typeof e.f.key === 'string') {
      keysOf[e.d].add(e.f.key)
    }
  }
  // A connection the tracer found already open has no open time.
  const opens = events.filter(
    (e) => e.e === 'conn.open' && typeof e.f.remote === 'string' && !e.f.late
  )
  const out = []
  for (let a = 0; a < devices.length; a++) {
    for (let b = a + 1; b < devices.length; b++) {
      const fromA = opens.filter((o) => o.d === a && keysOf[b].has(o.f.remote))
      const fromB = opens.filter((o) => o.d === b && keysOf[a].has(o.f.remote))
      const candidates = []
      for (const x of fromA) {
        for (const y of fromB) candidates.push({ x, y, delta: y.w - x.w })
      }
      candidates.sort((p, q) => Math.abs(p.delta) - Math.abs(q.delta))
      const used = new Set()
      const values = []
      for (const { x, y, delta } of candidates) {
        if (used.has(x) || used.has(y)) continue
        used.add(x)
        used.add(y)
        values.push(delta)
      }
      if (!values.length) continue
      out.push({
        a,
        b,
        ms: Math.round(median(values)),
        min: Math.round(Math.min(...values)),
        max: Math.round(Math.max(...values)),
        n: values.length
      })
    }
  }
  return out
}

/**
 * The data the page draws. Devices come from each event's `peer`, else
 * from its file name; files naming the same device merge. Events are
 * ordered by wall clock across devices.
 * @param {{ traces: Array<{ name: string, file?: string, events: object[], skipped?: number }>, failure?: object | null, topology?: object | null, net?: object[] | null, asserts?: any, title?: string }} input
 */
const buildModel = ({
  traces,
  failure = null,
  topology = null,
  net = null,
  asserts = null,
  title = 'Sync trace'
}) => {
  const devices = []
  const byName = new Map()
  const device = (name, file) => {
    let index = byName.get(name)
    if (index === undefined) {
      index = devices.length
      byName.set(name, index)
      devices.push({ name, files: [], count: 0, first: null, last: null })
    }
    if (file && !devices[index].files.includes(file)) {
      devices[index].files.push(file)
    }
    return index
  }
  const raw = []
  let skipped = 0
  let undated = 0
  for (const trace of traces) {
    skipped += trace.skipped ?? 0
    const file = trace.file ? path.basename(trace.file) : null
    for (const event of trace.events) {
      const wall = Date.parse(event.wall)
      if (Number.isNaN(wall)) {
        undated++
        continue
      }
      const name = str(event.peer) ?? trace.name
      raw.push({ event, wall, d: device(name, file) })
    }
  }
  raw.sort((a, b) => a.wall - b.wall)
  const t0 = raw.length ? raw[0].wall : 0
  const events = raw.map(({ event, wall, d }, i) => {
    const fields = {}
    for (const [key, value] of Object.entries(event)) {
      if (!META.has(key)) fields[key] = value
    }
    const dev = devices[d]
    dev.count++
    dev.first ??= new Date(wall).toISOString()
    dev.last = new Date(wall).toISOString()
    return {
      i,
      d,
      w: wall - t0,
      t: typeof event.t === 'number' ? event.t : null,
      e: str(event.event) ?? '?',
      l: str(event.label),
      f: fields
    }
  })
  return {
    title: String(title),
    generated: new Date().toISOString(),
    t0: raw.length ? new Date(t0).toISOString() : null,
    failure,
    devices,
    events,
    skew: estimateSkew(devices, events),
    topology,
    net: Array.isArray(net) ? net : null,
    asserts,
    warnings: [
      skipped ? `${skipped} unreadable line(s) skipped` : null,
      undated ? `${undated} event(s) without a wall clock skipped` : null
    ].filter(Boolean)
  }
}

const failureMessages = (failure) => {
  if (!failure) return []
  if (Array.isArray(failure.messages)) return failure.messages.map(String)
  if (typeof failure === 'string') return [failure]
  return [JSON.stringify(failure)]
}

/** @param {Parameters<typeof buildModel>[0]} input @returns {string} */
const renderReport = (input) => {
  const model = buildModel(input)
  const messages = failureMessages(model.failure)
  const banner = messages.length
    ? `<section class="banner" role="alert"><strong>Failed</strong>${messages
        .map((m) => `<pre>${escapeHtml(m)}</pre>`)
        .join('')}</section>`
    : ''
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>${escapeHtml(model.title)}</title>
<style>
${STYLE}
</style>
</head>
<body>
<header>
<h1>${escapeHtml(model.title)}</h1>
<p class="meta" id="summary">${escapeHtml(
    `${model.events.length} events from ${model.devices.length} device(s)`
  )}</p>
<button type="button" id="theme" aria-label="Switch light or dark">Theme</button>
</header>
${banner}
<main id="app"><noscript>The report needs JavaScript to draw; the data is embedded in this file.</noscript></main>
<script type="application/json" id="report-data">${embedJson(model)}</script>
<script>
${CLIENT}
</script>
</body>
</html>
`
}

/**
 * @param {Parameters<typeof buildModel>[0] & { out: string }} input
 * @returns {string} the path written
 */
const writeReport = ({ out, ...input }) => {
  fs.mkdirSync(path.dirname(out), { recursive: true })
  fs.writeFileSync(out, renderReport(input))
  return out
}

module.exports = {
  buildModel,
  deviceNameFromFile,
  escapeHtml,
  estimateSkew,
  loadJson,
  loadJsonl,
  loadTrace,
  renderReport,
  writeReport
}
