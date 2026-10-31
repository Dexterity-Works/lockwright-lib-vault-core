import fs from 'fs'
import path from 'path'

import { writeReport } from '../../scripts/trace-report/render.cjs'

/** Where failed runs leave their timelines; gitignored. */
export const artifactsRoot = () =>
  process.env.LOCKWRIGHT_NET_ARTIFACTS ||
  path.join(process.cwd(), 'test-artifacts')

export const slug = (name) =>
  name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 120) || 'test'

export const readTrace = (file) =>
  fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line))

const pad = (value, width) => String(value).padEnd(width)

const META = new Set(['t', 'wall', 'peer', 'event'])

const formatFields = (event) =>
  Object.entries(event)
    .filter(([key]) => !META.has(key))
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(' ')

/** One line per event, ordered by wall clock across peers. */
export const formatTimeline = (events) => {
  const start = events.length ? Date.parse(events[0].wall) : 0
  return events
    .map((event) => {
      const offset = ((Date.parse(event.wall) - start) / 1000).toFixed(3)
      return `+${pad(offset, 9)} ${pad(event.peer, 4)} ${pad(event.event, 20)} ${formatFields(event)}`
    })
    .join('\n')
}

/**
 * Merge per-peer JSONL traces into `<root>/<test slug>/timeline.{json,txt}`
 * and a self-contained report.html beside them.
 * @param {{ name: string, files: string[], failure?: object | null, root?: string }} options
 * @returns {{ dir: string, json: string, txt: string, html: string, events: object[] }}
 */
export const writeTimeline = ({ name, files, failure = null, root }) => {
  const events = files
    .filter((file) => fs.existsSync(file))
    .flatMap(readTrace)
    .sort((a, b) => Date.parse(a.wall) - Date.parse(b.wall))
  const dir = path.join(root ?? artifactsRoot(), slug(name))
  fs.mkdirSync(dir, { recursive: true })
  const json = path.join(dir, 'timeline.json')
  const txt = path.join(dir, 'timeline.txt')
  fs.writeFileSync(json, JSON.stringify({ name, failure, events }, null, 2))
  const header = [
    `# ${name}`,
    failure ? `# failed: ${failure.messages?.join(' | ') ?? ''}` : '# passed',
    `# ${events.length} events from ${files.length} peer(s)`,
    ''
  ].join('\n')
  fs.writeFileSync(txt, `${header}${formatTimeline(events)}\n`)
  const html = writeReport({
    out: path.join(dir, 'report.html'),
    title: name,
    failure,
    traces: [{ name: 'trace', events }]
  })
  return { dir, json, txt, html, events }
}
