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

// Collects the uncaught exceptions and unhandled rejections of the real
// process instead of letting jest fail whichever test is running when they
// land, so a test can assert the error a known bug throws. The test's own
// `process` is a copy; jest's handlers sit on this one.
const captureUncaught = () => {
  const events = ['uncaughtException', 'unhandledRejection']
  const saved = Object.fromEntries(
    events.map((event) => [event, process.listeners(event)])
  )
  const errors = []
  const collect = (error) => errors.push(error)
  for (const event of events) {
    process.removeAllListeners(event)
    process.on(event, collect)
  }
  return {
    errors,
    restore: () => {
      for (const event of events) {
        process.removeListener(event, collect)
        for (const listener of saved[event]) process.on(event, listener)
      }
    }
  }
}

class NetworkEnvironment extends TestEnvironment {
  constructor(config, context) {
    super(config, context)
    this.global.__lockwrightCaptureUncaught = captureUncaught
  }

  async handleTestEvent(event) {
    switch (event.name) {
      case 'test_start':
        this.global.__lockwrightNetworkTest = {
          name: fullName(event.test),
          failed: false,
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
      default:
    }
  }
}

module.exports = NetworkEnvironment
