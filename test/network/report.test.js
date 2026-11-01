import fs from 'fs'
import os from 'os'
import path from 'path'
import vm from 'vm'

import { buildModel, loadRun, parseLabLog, renderReport } from './report.js'
import { writeTimeline } from './timeline.js'

const wall = (ms) => new Date(Date.UTC(2026, 0, 1) + ms).toISOString()
const ev = (ms, peer, event, fields = {}) => ({
  t: ms,
  wall: wall(ms),
  peer,
  event,
  ...fields
})

/** The model a rendered page carries, read back out of its data tag. */
const modelOf = (html) => {
  const m = html.match(
    /<script type="application\/json" id="report-data">(.*?)<\/script>/s
  )
  return JSON.parse(m[1])
}

const LAB_LOG = [
  ' Container lwnet-x Creating ',
  "[lab 14:45:02] topology: peers=A B C nat=easy block_udp=1 relay=1 link_delay=5ms netem='loss 5%' bandwidth='' kill='B@signal' partition=''",
  '[lab 14:45:02] bootstrap listening 10.70.0.10:49737 (6 nodes: 49737, 49738)'
].join('\n')

const twoPeers = () => [
  ev(0, 'A', 'peer.start'),
  ev(1, 'A', 'swarm.create', { label: 'vault', key: 'aaaa1111' }),
  ev(2, 'B', 'peer.start'),
  ev(3, 'B', 'swarm.create', { label: 'vault', key: 'bbbb2222' }),
  ev(10, 'B', 'conn.open', {
    label: 'vault',
    remote: 'aaaa1111',
    initiator: true,
    path: 'direct',
    remoteAddress: '10.70.1.10:1'
  }),
  ev(11, 'A', 'conn.open', {
    label: 'vault',
    remote: 'bbbb2222',
    initiator: false,
    path: 'holepunched'
  }),
  ev(20, 'B', 'peer.offline'),
  ev(21, 'B', 'swarm.suspend', { label: 'vault' }),
  ev(22, 'B', 'conn.close', {
    label: 'vault',
    remote: 'aaaa1111',
    bytesRead: 10,
    bytesWritten: 20
  }),
  ev(23, 'A', 'error', {
    where: 'conn',
    code: 'ECONNRESET',
    message: 'reset',
    label: 'vault',
    remote: 'bbbb2222'
  }),
  ev(24, 'A', 'conn.close', { label: 'vault', remote: 'bbbb2222' }),
  ev(30, 'B', 'swarm.resume', { label: 'vault' }),
  ev(31, 'B', 'peer.online'),
  ev(40, 'A', 'autobase.update', {
    label: 'vault',
    length: 5,
    signedLength: 3,
    indexedLength: 4
  }),
  ev(41, 'A', 'epoch.status', {
    epoch: 'e1',
    seq: 1,
    legacy: false,
    canRead: true,
    revoked: false
  })
]

describe('network report', () => {
  test('pairs connection opens and closes and names the remote peer', () => {
    const model = buildModel({ name: 'pair', events: twoPeers() })
    expect(model.peers).toEqual(['A', 'B'])
    expect(model.duration).toBe(41)
    expect(model.conns).toEqual([
      expect.objectContaining({
        peer: 'B',
        remotePeer: 'A',
        path: 'direct',
        initiator: true,
        open: 10,
        close: 22,
        bytesRead: 10,
        bytesWritten: 20
      }),
      expect.objectContaining({
        peer: 'A',
        remotePeer: 'B',
        path: 'holepunched',
        open: 11,
        close: 24
      })
    ])
    expect(model.bands).toEqual(
      expect.arrayContaining([
        { peer: 'B', label: null, kind: 'offline', from: 20, to: 31 },
        { peer: 'B', label: 'vault', kind: 'suspend', from: 21, to: 30 }
      ])
    )
    expect(model.marks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'error',
          peer: 'A',
          label: 'vault',
          text: 'reset'
        }),
        expect.objectContaining({
          kind: 'epoch',
          peer: 'A',
          text: 'epoch 1, can read'
        })
      ])
    )
    expect(model.progress).toEqual([
      {
        peer: 'A',
        label: 'vault',
        t: 40,
        length: 5,
        signedLength: 3,
        indexedLength: 4
      }
    ])
    expect(model.failed).toBe(false)
    expect(model.topology).toEqual(
      expect.objectContaining({ layer: 1, peers: ['A', 'B'] })
    )
  })

  test('a killed peer’s connections end at the kill, not at the end of the run', () => {
    const events = [
      ...twoPeers().slice(0, 4),
      ev(10, 'B', 'conn.open', {
        label: 'vault',
        remote: 'aaaa1111',
        path: 'direct'
      }),
      // B is SIGKILLed at 50 and restarted at 60: no conn.close is ever traced.
      ev(60, 'B', 'peer.start'),
      ev(61, 'B', 'script.resume', { from: 3, fresh: false, remaining: 2 }),
      ev(70, 'B', 'conn.open', {
        label: 'vault',
        remote: 'aaaa1111',
        path: 'direct'
      })
    ]
    const model = buildModel({
      name: 'kill',
      events,
      faults: [{ kind: 'kill', peer: 'B', at: Date.parse(wall(50)) }]
    })
    const b = model.conns.filter((c) => c.peer === 'B')
    expect(b).toEqual([
      expect.objectContaining({ open: 10, close: 50, endedBy: 'kill' }),
      expect.objectContaining({ open: 70, close: null })
    ])
    expect(model.marks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'kill', peer: 'B', t: 50 }),
        expect.objectContaining({ kind: 'resume', peer: 'B', t: 61 })
      ])
    )
  })

  test('reads the lab topology line', () => {
    expect(parseLabLog(LAB_LOG)).toEqual({
      layer: 2,
      peers: ['A', 'B', 'C'],
      nat: 'easy',
      blockUdp: true,
      relay: true,
      linkDelay: '5ms',
      netem: 'loss 5%',
      bandwidth: '',
      kill: 'B@signal',
      partition: '',
      bootstrap: '10.70.0.10:49737',
      dhtNodes: 6
    })
    expect(parseLabLog('no topology here')).toBeNull()
  })

  test('renders one page that loads nothing and that no trace text can break out of', () => {
    const hostile = '</script><script>globalThis.pwned = 1</script>'
    const events = [
      ...twoPeers(),
      ev(50, 'A', 'script.fail', { message: hostile })
    ]
    const html = renderReport(
      buildModel({ name: hostile, events, failure: { messages: [hostile] } })
    )
    // The only script tags are the data tag and the page script.
    expect(html.match(/<script/g)).toHaveLength(2)
    expect(html.match(/<\/script>/g)).toHaveLength(2)
    expect(html).not.toContain(hostile)
    expect(html).toContain('<title>FAIL · &lt;/script&gt;')
    // Self-contained: no external loads of any kind.
    expect(html).not.toMatch(/\b(src|href)\s*=/i)
    expect(html).not.toMatch(/@import|url\(\s*['"]?https?:/i)
    expect(html).not.toMatch(/\bfetch\(|XMLHttpRequest|WebSocket|EventSource/)
    expect(
      (html.match(/https?:\/\/[^\s'"`)]+/g) ?? []).filter(
        (u) => u !== 'http://www.w3.org/2000/svg'
      )
    ).toEqual([])

    const model = modelOf(html)
    expect(model.failure).toEqual([hostile])
    expect(model.events).toHaveLength(events.length)

    // The inlined page script is plain browser JavaScript: it compiles, and no
    // module or transpiler residue leaked into it.
    const script = html.match(/<script>\n([\s\S]*?)\n<\/script>/)[1]
    expect(() => new vm.Script(script)).not.toThrow()
    expect(script).not.toMatch(/\brequire\(|\bexports\b|_interop|import\s/)
  })

  test('writeTimeline writes report.html beside the timeline', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'report-'))
    const file = path.join(dir, 'A.jsonl')
    fs.writeFileSync(
      file,
      twoPeers()
        .map((e) => JSON.stringify(e))
        .join('\n')
    )
    const out = writeTimeline({
      name: 'report › beside',
      files: [file],
      root: path.join(dir, 'artifacts')
    })
    expect(out.report).toBe(path.join(out.dir, 'report.html'))
    const model = modelOf(fs.readFileSync(out.report, 'utf8'))
    expect(model.name).toBe('report › beside')
    expect(model.topology.layer).toBe(1)
    expect(model.conns).toHaveLength(2)
    fs.rmSync(dir, { recursive: true, force: true })
  })

  test('a lab run gets its topology, faults, exits, scenario and logs', () => {
    const run = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-run-'))
    for (const sub of ['traces', 'logs', 'mailbox']) {
      fs.mkdirSync(path.join(run, sub))
    }
    const events = twoPeers()
    for (const peer of ['A', 'B']) {
      fs.writeFileSync(
        path.join(run, 'traces', `${peer}.jsonl`),
        events
          .filter((e) => e.peer === peer)
          .map((e) => JSON.stringify(e))
          .join('\n')
      )
    }
    fs.writeFileSync(path.join(run, 'logs', 'lab.log'), LAB_LOG)
    fs.writeFileSync(
      path.join(run, 'logs', 'assert.log'),
      'assertions passed: 2 rule(s)\n'
    )
    fs.writeFileSync(
      path.join(run, 'scenario.json'),
      JSON.stringify({
        name: 'lab',
        peers: {
          A: [{ op: 'createVault', id: 'shared' }],
          B: [{ op: 'pair', code: '$code' }, { op: 'offline' }]
        }
      })
    )
    fs.writeFileSync(path.join(run, 'exit.A'), '0\n')
    fs.writeFileSync(path.join(run, 'exit.B'), '1\n')
    fs.writeFileSync(
      path.join(run, 'mailbox', 'partition-start.B'),
      `${Date.parse(wall(12))}\n`
    )
    fs.writeFileSync(
      path.join(run, 'mailbox', 'partition-end.B'),
      `${Date.parse(wall(19))}\n`
    )

    // As run-lab does: the timeline lands in <run>/<scenario>/.
    const out = writeTimeline({
      name: 'lab',
      files: ['A', 'B'].map((p) => path.join(run, 'traces', `${p}.jsonl`)),
      root: run
    })
    const model = modelOf(fs.readFileSync(out.report, 'utf8'))
    expect(model.topology).toEqual(
      expect.objectContaining({ layer: 2, nat: 'easy', relay: true })
    )
    expect(model.exits).toEqual({ A: 0, B: 1 })
    expect(model.failed).toBe(true)
    expect(model.bands).toEqual(
      expect.arrayContaining([
        { peer: 'B', label: null, kind: 'partition', from: 12, to: 19 }
      ])
    )
    expect(model.planned.B).toEqual([
      { op: 'pair', text: 'pair code=$code' },
      { op: 'offline', text: 'offline' }
    ])
    expect(model.logs.assert).toContain('assertions passed')
    expect(model.logs.lab).toContain('topology: peers=A B C')
    expect(model.logs.lab).not.toContain('Creating')

    // The CLI's loader finds the same run from the run dir itself.
    expect(loadRun(run).outDir).toBe(out.dir)
    fs.rmSync(run, { recursive: true, force: true })
  })
})
