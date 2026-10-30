import { ddmin, generate, normalise, signature } from './schedule.js'

// The shrinking logic and the generator's preconditions, without a network.
describe('schedule minimiser and generator', () => {
  test('ddmin shrinks to the two items the predicate needs, in order', async () => {
    const items = Array.from({ length: 25 }, (_, i) => i)
    const seen = []
    const fails = async (c) => {
      seen.push(c)
      return c.includes(7) && c.includes(19)
    }
    const { steps, runs, exhausted } = await ddmin(items, fails)
    expect(steps).toEqual([7, 19])
    expect(exhausted).toBe(false)
    expect(runs).toBe(seen.length)
    expect(runs).toBeLessThan(60)
  })

  test('ddmin stops at the run budget with the smallest failing set so far', async () => {
    const items = Array.from({ length: 25 }, (_, i) => i)
    const { steps, runs, exhausted } = await ddmin(
      items,
      async (c) => c.includes(3),
      { maxRuns: 2 }
    )
    expect(runs).toBe(2)
    expect(exhausted).toBe(true)
    expect(steps).toContain(3)
    expect(steps.length).toBeLessThan(25)
  })

  test('a seed generates the same valid schedule every time', () => {
    const a = generate(42, { steps: 40 })
    expect(generate(42, { steps: 40 })).toEqual(a)
    expect(a).toHaveLength(40)
    expect(normalise(a)).toEqual(a)
  })

  test('normalise drops steps whose preconditions a shrink took away', () => {
    const steps = [
      { op: 'lock', peer: 'B' },
      { op: 'write', peer: 'B', key: 'note/1', value: { n: 1 } },
      { op: 'kick', by: 'A', target: 'A' },
      { op: 'kick', by: 'A', target: 'C' },
      { op: 'kick', by: 'A', target: 'B' },
      { op: 'write', peer: 'C', key: 'note/2', value: { n: 2 } },
      { op: 'remove', peer: 'A', key: 'note/9' },
      { op: 'rejoin', by: 'A', target: 'C' }
    ]
    expect(normalise(steps.slice(1))).toEqual([steps[1], steps[3], steps[7]])
    // B is locked: no write, and no kick of a locked device.
    expect(normalise(steps)).toEqual([steps[0], steps[3], steps[7]])
  })
  // Seeds are named in comments and findings: a change to the generator's
  // weights or draws changes what seed 1 means, and this notices.
  test('seed 1 still generates the same 15 steps', () => {
    const write = (peer, key, n) => ({
      op: 'write',
      peer,
      key,
      value: { k: key, n, by: peer }
    })
    expect(generate(1)).toEqual([
      { op: 'restart', peer: 'A' },
      { op: 'wait', ms: 212 },
      { op: 'wait', ms: 201 },
      write('A', 'note/0', 3),
      { op: 'offline', peer: 'B' },
      write('B', 'note/6', 5),
      write('C', 'note/2', 6),
      write('A', 'note/4', 7),
      write('A', 'note/6', 8),
      { op: 'wait', ms: 338 },
      { op: 'wait', ms: 417 },
      { op: 'epoch', peer: 'A' },
      write('C', 'note/7', 12),
      write('C', 'note/1', 13),
      write('B', 'note/3', 14)
    ])
  })

  test('a failure signature drops ids and numbers, not the clause or the step', () => {
    const key = (n, a, b) =>
      signature({
        invariant: 'convergence',
        message: `key note/${n}: ${a}={"n":4} ${b}=null`
      })
    expect(key(3, 'A', 'B')).toBe(key(5, 'B', 'C'))
    expect(key(3, 'A', 'B')).not.toBe(
      signature({
        invariant: 'convergence',
        message: 'epoch: waitFor: A, B settle unaided on one epoch'
      })
    )
    const step = (i, op, peer, message) =>
      signature(
        {
          invariant: `step:${op}`,
          message: `step ${i} (${op} peer=${peer}): ${message}`
        },
        { op, peer }
      )
    const hang = 'no result in 75000 ms'
    expect(step(4, 'write', 'C', hang)).toBe(step(9, 'write', 'C', hang))
    expect(step(4, 'write', 'C', hang)).not.toBe(step(4, 'write', 'B', hang))
    expect(step(4, 'write', 'C', hang)).not.toBe(
      step(4, 'write', 'C', 'SESSION_CLOSED: Cannot make sessions')
    )
  })
})
