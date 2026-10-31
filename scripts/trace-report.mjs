#!/usr/bin/env node
// node scripts/trace-report.mjs <trace.jsonl...> [--topology f] [--net f]
//   [--asserts f] [--failure text] [--title text] -o report.html
//
// One self-contained report.html from one or more traces: the harness's
// per-peer JSONL or timeline.json, or the traceFile of several devices, one
// file per device. Devices are named by the trace's `peer` field, else by
// the file name (laptop.jsonl -> laptop). Events merge by wall clock; the
// report shows the clock offsets it can estimate and does not correct them.
import { createRequire } from 'module'

const require = createRequire(import.meta.url)
const {
  loadJson,
  loadJsonl,
  loadTrace,
  writeReport
} = require('./trace-report/render.cjs')

const usage = () => {
  process.stderr.write(
    'usage: node scripts/trace-report.mjs <trace.jsonl...> [--topology f] [--net f] [--asserts f] [--failure text] [--title text] -o report.html\n'
  )
  process.exit(2)
}

const files = []
const opts = {}
const args = process.argv.slice(2)
for (let i = 0; i < args.length; i++) {
  const arg = args[i]
  const value = () => {
    if (i + 1 >= args.length) usage()
    return args[++i]
  }
  if (arg === '-o' || arg === '--out') opts.out = value()
  else if (arg === '--topology') opts.topology = value()
  else if (arg === '--net') opts.net = value()
  else if (arg === '--asserts') opts.asserts = value()
  else if (arg === '--failure') opts.failure = value()
  else if (arg === '--title') opts.title = value()
  else if (arg === '-h' || arg === '--help') usage()
  else if (arg.startsWith('-')) usage()
  else files.push(arg)
}
if (!files.length || !opts.out) usage()

const traces = files.map(loadTrace)
const fromTimeline = traces.find((t) => t.failure)?.failure ?? null
const out = writeReport({
  out: opts.out,
  traces,
  title: opts.title ?? traces.find((t) => t.title)?.title ?? 'Sync trace',
  failure: opts.failure ? { messages: [opts.failure] } : fromTimeline,
  topology: loadJson(opts.topology),
  net: loadJsonl(opts.net),
  asserts: loadJson(opts.asserts)
})
process.stdout.write(`${out}\n`)
