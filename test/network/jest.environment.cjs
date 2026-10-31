'use strict'
// Node environment plus the current test's name and failure state, so the
// harness can write a timeline from afterEach: jest-circus reports
// test_fn_failure before the afterEach hooks run.
const path = require('path')

// pnpm does not hoist jest-environment-node; walk jest's own dependency
// chain the way Node would from inside each package.
const resolveFrom = (from, name) =>
  require.resolve(name, {
    paths: [path.dirname(require.resolve(`${from}/package.json`))]
  })
const jestCli = resolveFrom('jest', 'jest-cli/package.json')
const jestConfig = require.resolve('jest-config/package.json', {
  paths: [path.dirname(jestCli)]
})
const { TestEnvironment } = require(
  require.resolve('jest-environment-node', {
    paths: [path.dirname(jestConfig)]
  })
)

const fullName = (test) => {
  const names = []
  for (
    let node = test;
    node && node.name !== 'ROOT_DESCRIBE_BLOCK';
    node = node.parent
  ) {
    names.unshift(node.name)
  }
  return names.join(' ')
}

const EVENTS = ['uncaughtException', 'unhandledRejection']

const listenerCounts = () =>
  Object.fromEntries(
    EVENTS.map((event) => [event, process.listenerCount(event)])
  )

// Collects the uncaught exceptions and unhandled rejections of the real
// process instead of letting jest fail whichever test is running when they
// land, so a test can assert the error a known bug throws. The test's own
// `process` is a copy; jest's handlers sit on this one. restore() puts
// jest's handlers back once, however often it is called.
const captureUncaught = () => {
  const saved = Object.fromEntries(
    EVENTS.map((event) => [event, process.listeners(event)])
  )
  const errors = []
  const collect = (error) => errors.push(error)
  for (const event of EVENTS) {
    process.removeAllListeners(event)
    process.on(event, collect)
  }
  let restored = false
  return {
    errors,
    saved,
    collect,
    get restored() {
      return restored
    },
    restore: () => {
      if (restored) return
      restored = true
      for (const event of EVENTS) {
        process.removeListener(event, collect)
        for (const listener of saved[event]) process.on(event, listener)
      }
    }
  }
}

class NetworkEnvironment extends TestEnvironment {
  constructor(config, context) {
    super(config, context)
    // One capture at a time. test_done restores it, so a test that times
    // out inside one does not leave jest's handlers replaced.
    this.capture = null
    this.global.__lockwrightCaptureUncaught = () => {
      this.capture?.restore()
      this.capture = captureUncaught()
      return this.capture
    }
    this.global.__lockwrightListenerCounts = listenerCounts
  }

  async handleTestEvent(event) {
    switch (event.name) {
      case 'test_start':
        this.global.__lockwrightNetworkTest = {
          name: fullName(event.test),
          failed: false,
          done: false,
          messages: []
        }
        break
      case 'test_fn_failure':
      case 'hook_failure': {
        const current = this.global.__lockwrightNetworkTest
        if (!current) break
        current.failed = true
        current.messages.push(event.error?.message ?? String(event.error))
        break
      }
      case 'test_done': {
        this.capture?.restore()
        this.capture = null
        // Tells work a timed-out test left running to stop.
        const current = this.global.__lockwrightNetworkTest
        if (current) current.done = true
        break
      }
      default:
    }
  }
}

module.exports = NetworkEnvironment
