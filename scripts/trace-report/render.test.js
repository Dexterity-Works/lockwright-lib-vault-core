import { spawnSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'

import {
  buildModel,
  deviceNameFromFile,
  loadTrace,
  renderReport
} from './render.cjs'

const jsonl = (events) => events.map((e) => JSON.stringify(e)).join('\n')
const at = (s) => new Date(Date.UTC(2026, 9, 31, 12, 0, s)).toISOString()

/** The JSON the page reads, parsed back out of the html. */
const embedded = (html) =>
  JSON.parse(
    html.match(
      /<script type="application\/json" id="report-data">([^<]*)<\/script>/
    )[1]
  )

describe('trace report', () => {
  let dir = null
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'report-'))
  })
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true })
  })

  test('merges device traces by wall clock and shows the clock offset', () => {
    // Two real devices: no peer field, so the file names them. The rotated
    // file is the same device. B's clock runs 2 s ahead of A's.
    const a = path.join(dir, 'laptop.jsonl')
    const a1 = path.join(dir, 'laptop.jsonl.1')
    const b = path.join(dir, 'phone.trace.jsonl')
    fs.writeFileSync(
      a1,
      jsonl([
        { t: 0, wall: at(0), peer: null, event: 'trace.start' },
        {
          t: 1,
          wall: at(1),
          peer: null,
          event: 'swarm.create',
          label: 'vault',
          key: 'aaaaaaaa'
        }
      ])
    )
    fs.writeFileSync(
      a,
      `${jsonl([
        {
          t: 9,
          wall: at(10),
          peer: null,
          event: 'conn.open',
          label: 'vault',
          remote: 'bbbbbbbb',
          path: 'direct'
        }
      ])}\nnot json\n`
    )
    fs.writeFileSync(
      b,
      jsonl([
        {
          t: 0,
          wall: at(3),
          event: 'swarm.create',
          label: 'vault',
          key: 'bbbbbbbb'
        },
        {
          t: 9,
          wall: at(12),
          event: 'conn.open',
          label: 'vault',
          remote: 'aaaaaaaa',
          path: 'direct'
        }
      ])
    )
    expect(deviceNameFromFile(b)).toBe('phone')
    expect(deviceNameFromFile(a1)).toBe('laptop')

    const model = buildModel({ traces: [a, b, a1].map(loadTrace) })
    expect(model.devices.map((d) => [d.name, d.count])).toEqual([
      ['laptop', 3],
      ['phone', 2]
    ])
    expect(model.devices[0].files).toEqual(['laptop.jsonl', 'laptop.jsonl.1'])
    expect(model.events.map((e) => [e.d, e.e, e.w])).toEqual([
      [0, 'trace.start', 0],
      [0, 'swarm.create', 1000],
      [1, 'swarm.create', 3000],
      [0, 'conn.open', 10000],
      [1, 'conn.open', 12000]
    ])
    expect(model.events[3]).toMatchObject({
      l: 'vault',
      f: { remote: 'bbbbbbbb', path: 'direct' }
    })
    expect(model.skew).toEqual([
      { a: 0, b: 1, ms: 2000, min: 2000, max: 2000, n: 1 }
    ])
    expect(model.warnings).toEqual(['1 unreadable line(s) skipped'])
  })

  test('the peer field names harness devices; a timeline.json reads too', () => {
    const file = path.join(dir, 'timeline.json')
    fs.writeFileSync(
      file,
      JSON.stringify({
        name: 'partition › heals',
        failure: { messages: ['boom'] },
        events: [
          { t: 0, wall: at(0), peer: 'A', event: 'peer.start' },
          { t: 0, wall: at(1), peer: 'B', event: 'peer.start' }
        ]
      })
    )
    const trace = loadTrace(file)
    expect(trace).toMatchObject({
      title: 'partition › heals',
      failure: { messages: ['boom'] }
    })
    expect(buildModel({ traces: [trace] }).devices.map((d) => d.name)).toEqual([
      'A',
      'B'
    ])
  })

  test('escapes markup in every field, since trace values are untrusted', () => {
    const evil = '</script><img src=x onerror=alert(1)>&<b>"\'\u2028'
    const html = renderReport({
      title: evil,
      failure: { messages: [evil] },
      traces: [
        {
          name: 'file',
          events: [
            {
              t: 0,
              wall: at(0),
              peer: evil,
              event: evil,
              label: evil,
              [evil]: evil,
              nested: { deep: [evil] }
            },
            { t: 1, wall: at(1), event: 'conn.fail', label: evil, code: evil }
          ]
        }
      ],
      topology: { nodes: [{ id: evil, label: evil }], links: [] },
      net: [{ from: evil, to: evil, drops: evil }],
      asserts: [{ name: evil, pass: false, message: evil }]
    })
    expect(html).not.toContain('<img')
    expect(html).not.toContain('<b>')
    // A raw line separator would end a string inside the script.
    expect(html.slice(html.indexOf('id="report-data"'))).not.toContain('\u2028')
    expect(html.match(/<script/g)).toHaveLength(2)
    expect(html.match(/<\/script>/g)).toHaveLength(2)
    expect(html).toContain('&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;')
    // The data still reads back whole.
    const model = embedded(html)
    expect(model.title).toBe(evil)
    expect(model.devices.map((d) => d.name)).toEqual([evil, 'file'])
    expect(model.events[0]).toMatchObject({
      e: evil,
      l: evil,
      f: { [evil]: evil, nested: { deep: [evil] } }
    })
    expect(model.events[1].d).toBe(1)
    expect(model.topology.nodes[0].label).toBe(evil)
    expect(model.net[0].drops).toBe(evil)
    expect(model.asserts[0].message).toBe(evil)
  })

  test('the page makes no requests and fetches nothing', () => {
    const html = renderReport({ traces: [{ name: 'A', events: [] }] })
    expect(html).toContain("default-src 'none'")
    expect(html).not.toMatch(/\b(src|href)=["']?(https?:)?\/\//i)
    expect(html).not.toMatch(/\bfetch\(|XMLHttpRequest|import\(/)
  })

  test('the CLI writes one report from several device files', () => {
    const a = path.join(dir, 'laptop.jsonl')
    const b = path.join(dir, 'phone.jsonl')
    fs.writeFileSync(a, jsonl([{ t: 0, wall: at(0), event: 'trace.start' }]))
    fs.writeFileSync(b, jsonl([{ t: 0, wall: at(1), event: 'trace.start' }]))
    const topology = path.join(dir, 'topology.json')
    fs.writeFileSync(topology, JSON.stringify({ nodes: [], links: [] }))
    const out = path.join(dir, 'out', 'report.html')
    const result = spawnSync(
      process.execPath,
      [
        path.join(__dirname, '..', 'trace-report.mjs'),
        a,
        b,
        '--topology',
        topology,
        '-o',
        out
      ],
      { encoding: 'utf8' }
    )
    expect(result.stderr).toBe('')
    expect(result.status).toBe(0)
    expect(result.stdout.trim()).toBe(out)
    const model = embedded(fs.readFileSync(out, 'utf8'))
    expect(model.devices.map((d) => d.name)).toEqual(['laptop', 'phone'])
    expect(model.topology).toEqual({ nodes: [], links: [] })
  })
})
