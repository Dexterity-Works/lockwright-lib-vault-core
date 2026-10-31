// The uncaught-error capture in test/network/jest.environment.cjs. It swaps
// jest's handlers on the real process out, so it must put them back exactly
// once, and on its own when a test ends inside it.
const capture = () => globalThis.__lockwrightCaptureUncaught()
const counts = () => globalThis.__lockwrightListenerCounts()

describe('uncaught-error capture', () => {
  let leftOpen = null
  let before = null

  test('restore puts jest handlers back once, however often it is called', () => {
    before = counts()
    const caught = capture()
    expect(counts()).toEqual({ uncaughtException: 1, unhandledRejection: 1 })
    caught.restore()
    expect(counts()).toEqual(before)
    caught.restore()
    expect(counts()).toEqual(before)
  })

  test('a capture still open when its test ends', () => {
    leftOpen = capture()
    expect(counts()).toEqual({ uncaughtException: 1, unhandledRejection: 1 })
  })

  test('is restored by the environment at test_done', () => {
    expect(leftOpen.restored).toBe(true)
    expect(counts()).toEqual(before)
    const caught = capture()
    try {
      // What this capture saved is jest's handlers again, not the last
      // test's collector.
      for (const event of ['uncaughtException', 'unhandledRejection']) {
        expect(caught.saved[event]).not.toContain(leftOpen.collect)
        expect(caught.saved[event].length).toBeGreaterThan(0)
      }
    } finally {
      caught.restore()
    }
  })
})
