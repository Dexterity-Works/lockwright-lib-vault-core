import { spawn } from 'child_process'
import crypto from 'crypto'
import fs from 'fs'
import path from 'path'

import { mkdtemp, removeDir } from './tmp.js'

// Finding 4 (PROGRESS-network): a lab peer SIGKILLed during its first
// master-vault open could not reopen it ("failed to rotate"). This kills a
// real child process at increasing delays after it starts masterVaultInit
// and reopens the store with the same keys; and, as the control, reopens
// with a different hashedPassword, which is what the lab's resumed peer did.

const root = path.resolve(__dirname, '..', '..')
const child = path.join(root, 'test', 'network', 'child', 'master-init.mjs')
const register = path.join(root, 'test', 'network', 'child', 'register.mjs')

const procs = new Set()
const run = (dir, keys, { killAfterOpeningMs = null } = {}) =>
  new Promise((resolve) => {
    const proc = spawn(
      process.execPath,
      [
        '--import',
        register,
        child,
        dir,
        keys.encryptionKey,
        keys.hashedPassword
      ],
      {
        cwd: root,
        env: { ...process.env, NODE_OPTIONS: '' },
        stdio: ['ignore', 'pipe', 'pipe']
      }
    )
    procs.add(proc)
    let out = ''
    let killed = false
    proc.stdout.on('data', (chunk) => {
      out += chunk
      if (killAfterOpeningMs !== null && !killed && out.includes('opening')) {
        killed = true
        setTimeout(() => proc.kill('SIGKILL'), killAfterOpeningMs)
      }
    })
    proc.stderr.on('data', (chunk) => {
      out += chunk
    })
    // 'close', not 'exit': stdio can still hold the last lines at 'exit'.
    proc.on('close', (code, signal) => {
      procs.delete(proc)
      resolve({ code, signal, out })
    })
  })

const keys = () => ({
  encryptionKey: crypto.randomBytes(32).toString('base64'),
  hashedPassword: crypto.randomBytes(32).toString('hex')
})

const files = (dir) =>
  fs
    .readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile()).length

describe('master vault killed during its first open (Finding 4)', () => {
  const dirs = []
  // Where each kill landed: inside masterVaultInit, inside vaultsAdd, or
  // after the open; and whether the store had files by then.
  const landed = []
  afterEach(() => {
    // A child that hung (a reopen stuck on a lock) must not outlive its test
    // or see its storage dir removed under it.
    for (const proc of procs) proc.kill('SIGKILL')
    procs.clear()
  })
  afterAll(() => dirs.forEach((d) => removeDir(d)))

  test.each([0, 2, 5, 10, 20, 40, 60, 80, 120, 160])(
    'killed %i ms into the first open, it reopens with the same keys',
    async (ms) => {
      const dir = mkdtemp('masterkill')
      dirs.push(dir)
      const k = keys()
      const first = await run(dir, k, { killAfterOpeningMs: ms })
      landed.push({
        ms,
        phase: first.out.includes('opened')
          ? 'after'
          : first.out.includes('inited')
            ? 'vaultsAdd'
            : 'masterVaultInit',
        files: files(dir)
      })
      const reopened = await run(dir, k)
      expect(reopened.out.trim().split('\n').pop()).toBe('opened')
    },
    60000
  )

  test('the kills covered the open, not only an empty or finished store', () => {
    // Host speed decides which delays land where; the run is only worth
    // something if several kills interrupted an open that had written files.
    const inside = landed.filter((l) => l.phase !== 'after' && l.files > 0)
    expect(landed).toHaveLength(10)
    expect(inside.length).toBeGreaterThanOrEqual(3)
    expect(inside.some((l) => l.phase === 'masterVaultInit')).toBe(true)
  })

  test('reopening with a different hashedPassword fails with "failed to rotate" (the lab resume bug)', async () => {
    const dir = mkdtemp('masterkill')
    dirs.push(dir)
    const k = keys()
    expect((await run(dir, k)).out).toContain('opened')
    const other = {
      ...k,
      hashedPassword: crypto.randomBytes(32).toString('hex')
    }
    const res = await run(dir, other)
    expect(res.code).toBe(1)
    expect(res.out).toContain('failed to rotate')
  }, 60000)
})
