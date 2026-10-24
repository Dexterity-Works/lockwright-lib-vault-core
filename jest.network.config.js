import base from './jest.config.js'

// Network harness: real Hyperswarm peers on a local hyperdht testnet.
// Separate from `pnpm test` so the unit suite stays fast; run with
// `pnpm test:network`.
export default {
  ...base,
  testMatch: ['<rootDir>/test/network/**/*.test.js'],
  testPathIgnorePatterns: ['/node_modules/'],
  setupFiles: [...base.setupFiles, '<rootDir>/test/network/jest.guard.cjs'],
  moduleNameMapper: {
    ...base.moduleNameMapper,
    // Bare-only modules, so the worklet code runs under Node for the harness
    '^bare-fs$': '<rootDir>/test/network/shims/bare-fs.cjs',
    '^bare-path$': '<rootDir>/test/network/shims/bare-path.cjs',
    '^bare-os$': '<rootDir>/test/network/shims/bare-os.cjs',
    '^bare-file-logger$': '<rootDir>/test/network/shims/noop-logger.cjs',
    '^bare-system-logger$': '<rootDir>/test/network/shims/noop-logger.cjs'
  },
  testTimeout: 120000
}
