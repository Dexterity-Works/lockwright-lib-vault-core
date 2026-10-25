import { spawnSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'

import { formatTimeline, slug, writeTimeline } from './timeline.js'

const root = path.resolve(__dirname, '..', '..')

describe('timeline artifacts', () => {
  test('merges per-peer traces by wall clock', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'timeline-'))
    const a = path.join(dir, 'A.jsonl')
    const b = path.join(dir, 'B.jsonl')
    fs.writeFileSync(
      a,
      [
        { t: 0, wall: '2026-01-01T00:00:00.000Z', peer: 'A', event: 'first' },
        {
          t: 9,
          wall: '2026-01-01T00:00:02.000Z',
          peer: 'A',
          event: 'third',
          n: 3
        }
      ]
        .map((e) => JSON.stringify(e))
        .join('\n')
    )
    fs.writeFileSync(
      b,
      `${JSON.stringify({ t: 0, wall: '2026-01-01T00:00:01.000Z', peer: 'B', event: 'second' })}\n`
    )
    const out = writeTimeline({
      name: 'merge › works',
      files: [a, b, path.join(dir, 'missing.jsonl')],
      failure: { messages: ['boom'] },
      root: path.join(dir, 'artifacts')
    })
    expect(out.dir).toBe(path.join(dir, 'artifacts', 'merge-works'))
    expect(out.events.map((e) => e.event)).toEqual(['first', 'second', 'third'])
    const txt = fs.readFileSync(out.txt, 'utf8')
    expect(txt).toContain('# failed: boom')
    expect(txt.split('\n').filter((l) => l.startsWith('+'))).toEqual([
      expect.stringMatching(/^\+0\.000\s+A\s+first/),
      expect.stringMatching(/^\+1\.000\s+B\s+second/),
      expect.stringMatching(/^\+2\.000\s+A\s+third\s+n=3/)
    ])
    const json = JSON.parse(fs.readFileSync(out.json, 'utf8'))
    expect(json.failure).toEqual({ messages: ['boom'] })
    expect(json.events).toHaveLength(3)
    expect(formatTimeline([])).toBe('')
    expect(slug('  Weird / Name!! ')).toBe('weird-name')
    fs.rmSync(dir, { recursive: true, force: true })
  })

  test('a failing network test leaves a timeline and prints its path', () => {
    const artifacts = fs.mkdtempSync(path.join(os.tmpdir(), 'artifacts-'))
    const result = spawnSync(
      'pnpm',
      [
        'exec',
        'jest',
        '--config',
        'jest.network.config.js',
        '--runInBand',
        '--testMatch',
        '**/test/network/fixtures/*.network.js',
        'test/network/fixtures/failing.network.js'
      ],
      {
        cwd: root,
        encoding: 'utf8',
        env: { ...process.env, LOCKWRIGHT_NET_ARTIFACTS: artifacts, CI: '1' },
        timeout: 110000
      }
    )
    const output = `${result.stdout}\n${result.stderr}`
    expect(result.status).toBe(1)
    expect(output).toContain('fails after creating a vault')
    const dir = path.join(
      artifacts,
      'forced-failure-fails-after-creating-a-vault'
    )
    expect(output).toContain(`timeline: ${path.join(dir, 'timeline.txt')}`)
    const txt = fs.readFileSync(path.join(dir, 'timeline.txt'), 'utf8')
    expect(txt).toContain('# failed:')
    expect(txt).toMatch(/\bA\s+peer\.createVault\b/)
    expect(txt).toMatch(/\bB\s+swarm\.create\b/)
    const json = JSON.parse(
      fs.readFileSync(path.join(dir, 'timeline.json'), 'utf8')
    )
    expect(json.failure.messages.join()).toContain('nothing-like-it')
    expect(
      json.events.some((e) => e.peer === 'A' && e.event === 'autobase.append')
    ).toBe(true)
    fs.rmSync(artifacts, { recursive: true, force: true })
  })
})
