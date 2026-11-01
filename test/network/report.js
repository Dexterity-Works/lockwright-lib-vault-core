// Render a run's traces as one self-contained report.html. writeTimeline calls
// writeReport; report-cli.js renders any run dir or timeline.json by hand.
import fs from 'fs'
import path from 'path'

import { reportPage } from './report-client.js'
import { reportCss } from './report-style.js'
import { readTrace } from './timeline.js'

const LABEL_ORDER = [
  'pairer',
  'master',
  'vault',
  'personalSwarm',
  'personalSend',
  'sharedDHT'
]
const labelRank = (label) => {
  const i = LABEL_ORDER.indexOf(label)
  return i === -1 ? LABEL_ORDER.length : i
}

const ERROR_EVENTS = new Set([
  'error',
  'script.fail',
  'uncaught.recoverable',
  'peer.stop.timeout'
])

/** The `topology:` and `bootstrap listening` lines run-lab's topology.sh writes to lab.log. */
export const parseLabLog = (text) => {
  const line = text.split('\n').find((l) => l.includes('] topology: peers='))
  if (!line) return null
  const body = line.slice(line.indexOf('topology: ') + 'topology: '.length)
  const peers = (body.match(/peers=(.*?) nat=/)?.[1] ?? '')
    .split(' ')
    .filter(Boolean)
  const field = (name) => {
    const m = body.match(new RegExp(`\\b${name}=('([^']*)'|(\\S+))`))
    return m ? (m[2] ?? m[3]) : ''
  }
  const boot = text.match(/bootstrap listening (\S+) \((\d+) nodes/)
  return {
    layer: 2,
    peers,
    nat: field('nat'),
    blockUdp: field('block_udp') === '1',
    relay: field('relay') === '1',
    linkDelay: field('link_delay'),
    netem: field('netem'),
    bandwidth: field('bandwidth'),
    kill: field('kill'),
    partition: field('partition'),
    bootstrap: boot ? boot[1] : null,
    dhtNodes: boot ? Number(boot[2]) : null
  }
}

const readText = (file) =>
  fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null

/** Fault times from the lab mailbox: partition stamps hold epoch ms, a kill marker's mtime is the kill. */
const readFaults = (mailboxDir) => {
  const faults = []
  if (!mailboxDir || !fs.existsSync(mailboxDir)) return faults
  const files = fs.readdirSync(mailboxDir)
  for (const file of files) {
    const start = file.match(/^partition-start\.(.+)$/)
    if (start) {
      const peer = start[1]
      const from = Number(
        fs.readFileSync(path.join(mailboxDir, file), 'utf8').trim()
      )
      const endFile = path.join(mailboxDir, `partition-end.${peer}`)
      const to = fs.existsSync(endFile)
        ? Number(fs.readFileSync(endFile, 'utf8').trim())
        : null
      faults.push({ kind: 'partition', peer, from, to })
    }
    const killed = file.match(/^killed\.(.+)$/)
    if (killed) {
      faults.push({
        kind: 'kill',
        peer: killed[1],
        at: fs.statSync(path.join(mailboxDir, file)).mtimeMs
      })
    }
  }
  return faults
}

const META = new Set(['t', 'wall', 'peer', 'event'])
const fieldsOf = (event) =>
  Object.fromEntries(Object.entries(event).filter(([key]) => !META.has(key)))

/** Everything the page draws, computed here so the browser script only renders. */
export const buildModel = ({
  name,
  failure = null,
  events,
  topology = null,
  scenario = null,
  faults = [],
  exits = {},
  logs = {},
  source = null
}) => {
  const sorted = [...events].sort(
    (a, b) => Date.parse(a.wall) - Date.parse(b.wall)
  )
  const t0 = sorted.length ? Date.parse(sorted[0].wall) : 0
  const rel = (wallMs) => wallMs - t0
  const duration = sorted.length ? Date.parse(sorted.at(-1).wall) - t0 : 0
  const peers = [...new Set(sorted.map((e) => e.peer))].sort()

  // Swarm public keys, so a connection's remote key names a peer.
  const keys = {}
  for (const e of sorted) {
    if (e.event === 'swarm.create' && e.key)
      keys[e.key] = { peer: e.peer, label: e.label }
  }

  const rows = sorted.map((e, i) => ({
    i,
    t: rel(Date.parse(e.wall)),
    peer: e.peer,
    event: e.event,
    f: fieldsOf(e)
  }))

  const conns = []
  const openConns = new Map()
  const bands = []
  const openBands = new Map()
  const marks = []
  const steps = []
  const progress = []
  const started = new Set()
  for (const row of rows) {
    const { peer, event, f, t } = row
    // A second peer.start is a restarted process: the old one's connections died with it.
    if (event === 'peer.start') {
      if (started.has(peer)) {
        for (const [key, list] of openConns) {
          if (!key.startsWith(`${peer}|`)) continue
          for (const conn of list) {
            conn.close = t
            conn.endedBy = 'restart'
          }
          openConns.delete(key)
        }
      }
      started.add(peer)
    }
    if (event === 'conn.open') {
      const key = `${peer}|${f.label}|${f.remote}`
      const conn = {
        peer,
        label: f.label,
        remote: f.remote,
        remotePeer: keys[f.remote]?.peer ?? null,
        path: f.path ?? 'unknown',
        initiator: !!f.initiator,
        remoteAddress: f.remoteAddress ?? null,
        open: t,
        close: null,
        openIndex: row.i
      }
      conns.push(conn)
      if (!openConns.has(key)) openConns.set(key, [])
      openConns.get(key).push(conn)
    } else if (event === 'conn.upgrade') {
      const conn = openConns.get(`${peer}|${f.label}|${f.remote}`)?.at(-1)
      if (conn && f.path) conn.path = f.path
    } else if (event === 'conn.close') {
      const conn = openConns.get(`${peer}|${f.label}|${f.remote}`)?.shift()
      if (conn) {
        conn.close = t
        conn.bytesRead = f.bytesRead
        conn.bytesWritten = f.bytesWritten
        conn.closeIndex = row.i
      }
    }

    if (event === 'peer.offline')
      openBands.set(`${peer}|offline`, {
        peer,
        label: null,
        kind: 'offline',
        from: t,
        to: null
      })
    if (event === 'peer.online') {
      const band = openBands.get(`${peer}|offline`)
      if (band) {
        band.to = t
        bands.push(band)
        openBands.delete(`${peer}|offline`)
      }
    }
    if (event === 'swarm.suspend')
      openBands.set(`${peer}|${f.label}|suspend`, {
        peer,
        label: f.label,
        kind: 'suspend',
        from: t,
        to: null
      })
    if (event === 'swarm.resume') {
      const band = openBands.get(`${peer}|${f.label}|suspend`)
      if (band) {
        band.to = t
        bands.push(band)
        openBands.delete(`${peer}|${f.label}|suspend`)
      }
    }

    if (ERROR_EVENTS.has(event) || (event === 'guard.breaches' && f.n > 0)) {
      marks.push({
        kind: 'error',
        peer,
        t,
        label: f.label ?? null,
        text: f.message ?? f.code ?? event,
        i: row.i
      })
    }
    if (event === 'script.resume')
      marks.push({
        kind: 'resume',
        peer,
        t,
        text: `resumed at step ${f.from}`,
        i: row.i
      })
    if (event === 'epoch.status') {
      const text = f.revoked
        ? 'revoked'
        : f.legacy
          ? 'legacy (no epoch)'
          : f.canRead
            ? `epoch ${f.seq}, can read`
            : `epoch ${f.seq}, cannot read`
      marks.push({ kind: 'epoch', peer, t, text, i: row.i })
    }
    if (
      event === 'script.step' ||
      event === 'script.done' ||
      event === 'script.fail' ||
      event.startsWith('peer.')
    ) {
      steps.push({
        peer,
        t,
        event,
        index: f.index ?? null,
        op: f.op ?? null,
        f,
        i: row.i
      })
    }
    if (event === 'autobase.update' || event === 'autobase.open') {
      progress.push({
        peer,
        label: f.label,
        t,
        length: f.length ?? 0,
        signedLength: f.signedLength ?? 0,
        indexedLength: f.indexedLength ?? 0
      })
    }
  }
  for (const band of openBands.values()) bands.push(band)

  for (const fault of faults) {
    if (fault.kind === 'partition') {
      bands.push({
        peer: fault.peer,
        label: null,
        kind: 'partition',
        from: rel(fault.from),
        to: fault.to ? rel(fault.to) : null
      })
    }
    if (fault.kind === 'kill') {
      const at = rel(fault.at)
      marks.push({ kind: 'kill', peer: fault.peer, t: at, text: 'SIGKILL' })
      for (const conn of conns) {
        if (
          conn.peer === fault.peer &&
          conn.endedBy === 'restart' &&
          conn.open <= at &&
          conn.close > at
        ) {
          conn.close = at
          conn.endedBy = 'kill'
        }
      }
    }
  }

  const planned = {}
  if (scenario?.peers) {
    for (const [peer, list] of Object.entries(scenario.peers)) {
      planned[peer] = list.map((step) => ({
        op: step.op,
        text: describeStep(step)
      }))
    }
  }

  const labels = [...new Set(conns.map((c) => c.label))].sort(
    (a, b) => labelRank(a) - labelRank(b)
  )

  const failed = !!failure || Object.values(exits).some((code) => code !== 0)
  return {
    name,
    source,
    generated: new Date().toISOString(),
    startWall: sorted[0]?.wall ?? null,
    duration,
    failed,
    failure: failure?.messages ?? [],
    peers,
    labels,
    exits,
    keys,
    topology: topology ?? {
      layer: 1,
      peers,
      bootstrap:
        sorted.find((e) => e.event === 'swarm.create')?.bootstrap ?? null
    },
    events: rows,
    conns,
    bands,
    marks,
    steps,
    planned,
    progress,
    logs
  }
}

const describeStep = (step) => {
  const { op, ...rest } = step
  const parts = Object.entries(rest)
    .filter(([key]) => key !== 'data')
    .map(
      ([key, value]) =>
        `${key}=${typeof value === 'string' ? value : JSON.stringify(value)}`
    )
  return parts.length ? `${op} ${parts.join(' ')}` : op
}

/** The model as an inline script; `<` is escaped so no string can close the tag. */
const embed = (model) => JSON.stringify(model).replace(/</g, '\\u003c')

export const renderReport = (model) => {
  const js = `;(${reportPage.toString()})()`
  if (/<\/(script|style)/i.test(js + reportCss)) {
    throw new Error('report: page source would close its own tag')
  }
  const title = `${model.failed ? 'FAIL' : 'ok'} · ${model.name}`
  const escapeHtml = (s) =>
    s.replace(
      /[&<>"]/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]
    )
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
${reportCss}
</style>
</head>
<body class="viz-root">
<main id="app"></main>
<div id="tip" role="tooltip" hidden></div>
<script type="application/json" id="report-data">${embed(model)}</script>
<script>
${js}
</script>
</body>
</html>
`
}

/** Read whatever a run left behind: a timeline.json, a jest artifact dir, or a lab run dir. */
export const loadRun = (input) => {
  const stat = fs.statSync(input)
  let timelineFile = null
  let runDir = null
  if (stat.isFile()) {
    timelineFile = input
  } else if (fs.existsSync(path.join(input, 'timeline.json'))) {
    timelineFile = path.join(input, 'timeline.json')
  } else {
    runDir = input
    const sub = fs
      .readdirSync(input, { withFileTypes: true })
      .find(
        (d) =>
          d.isDirectory() &&
          fs.existsSync(path.join(input, d.name, 'timeline.json'))
      )
    if (sub) timelineFile = path.join(input, sub.name, 'timeline.json')
  }
  // A lab run keeps its timeline one level down: <run>/<scenario>/timeline.json.
  if (timelineFile && !runDir) {
    const parent = path.dirname(path.dirname(timelineFile))
    if (
      fs.existsSync(path.join(parent, 'traces')) &&
      fs.existsSync(path.join(parent, 'logs'))
    )
      runDir = parent
  }

  let name = path.basename(runDir ?? path.dirname(timelineFile ?? input))
  let failure = null
  let events = []
  if (timelineFile) {
    const timeline = JSON.parse(fs.readFileSync(timelineFile, 'utf8'))
    name = timeline.name ?? name
    failure = timeline.failure ?? null
    events = timeline.events ?? []
  } else if (runDir && fs.existsSync(path.join(runDir, 'traces'))) {
    const tracesDir = path.join(runDir, 'traces')
    events = fs
      .readdirSync(tracesDir)
      .filter((f) => f.endsWith('.jsonl'))
      .flatMap((f) => readTrace(path.join(tracesDir, f)))
  } else {
    throw new Error(`no timeline.json or traces/ under ${input}`)
  }

  const options = { name, failure, events, source: path.resolve(input) }
  if (runDir) {
    const labLog = readText(path.join(runDir, 'logs', 'lab.log'))
    const assertLog = readText(path.join(runDir, 'logs', 'assert.log'))
    const scenarioText = readText(path.join(runDir, 'scenario.json'))
    options.topology = labLog ? parseLabLog(labLog) : null
    options.scenario = scenarioText ? JSON.parse(scenarioText) : null
    options.faults = readFaults(path.join(runDir, 'mailbox'))
    options.exits = Object.fromEntries(
      fs
        .readdirSync(runDir)
        .filter((f) => f.startsWith('exit.'))
        .map((f) => [
          f.slice('exit.'.length),
          Number(fs.readFileSync(path.join(runDir, f), 'utf8').trim())
        ])
    )
    options.logs = {
      lab:
        labLog
          ?.split('\n')
          .filter((l) => !/Container .* (Creating|Created)/.test(l))
          .join('\n') ?? null,
      assert: assertLog
    }
  }
  const outDir = timelineFile ? path.dirname(timelineFile) : runDir
  return { model: buildModel(options), outDir }
}

export const writeReport = (input, out) => {
  const { model, outDir } = loadRun(input)
  const file = out ?? path.join(outDir, 'report.html')
  fs.writeFileSync(file, renderReport(model))
  return file
}
