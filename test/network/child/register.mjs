// Preloaded with `node --import` for child processes of the network tests
// (a peer the test can SIGKILL). Same mapping as jest.network.config.js:
// Bare-only modules to Node, the swarmconf stub, the `.js` the worklet
// leaves off relative imports, and hyperdht, hyperswarm and udx-native
// through the public-DHT guard.
import fs from 'fs'
import module from 'module'
import path from 'path'
import { fileURLToPath, pathToFileURL } from 'url'

const here = path.dirname(fileURLToPath(import.meta.url))
const pkg = path.resolve(here, '..', '..', '..')
const file = (...parts) => pathToFileURL(path.join(...parts)).href

const direct = {
  'bare-fs': 'fs',
  'bare-path': 'path',
  'bare-os': 'os',
  'bare-file-logger': file(here, '..', 'shims', 'noop-logger.cjs'),
  'bare-system-logger': file(here, '..', 'shims', 'noop-logger.cjs'),
  '@tetherto/swarmconf': file(pkg, 'test-stubs', 'swarmconf.js')
}
const real = (globalThis.__lockwrightReal ??= {})
const guarded = {
  hyperdht: file(here, 'guarded', 'hyperdht.cjs'),
  hyperswarm: file(here, 'guarded', 'hyperswarm.cjs'),
  'udx-native': file(here, 'guarded', 'udx-native.cjs')
}
globalThis.__lockwrightGuardPath = path.join(here, '..', 'guard.cjs')
const guardedDir = file(here, 'guarded') + '/'

const resolveReal = (specifier, context, nextResolve) => {
  try {
    return nextResolve(specifier, context)
  } catch (error) {
    const relative = specifier.startsWith('./') || specifier.startsWith('../')
    if (
      error.code !== 'ERR_MODULE_NOT_FOUND' ||
      !relative ||
      !context.parentURL
    )
      throw error
    const base = fileURLToPath(new URL(specifier, context.parentURL))
    for (const suffix of ['.js', '/index.js']) {
      if (fs.existsSync(base + suffix))
        return nextResolve(base + suffix, context)
    }
    throw error
  }
}

module.registerHooks({
  resolve(specifier, context, nextResolve) {
    if (direct[specifier]) return nextResolve(direct[specifier], context)
    if (guarded[specifier] && !context.parentURL?.startsWith(guardedDir)) {
      const resolved = resolveReal(specifier, context, nextResolve)
      real[specifier] ??= resolved.url
      if (real[specifier] !== resolved.url) {
        throw new Error(
          `two copies of ${specifier}: ${real[specifier]} and ${resolved.url}`
        )
      }
      return { url: guarded[specifier], format: 'commonjs', shortCircuit: true }
    }
    return resolveReal(specifier, context, nextResolve)
  }
})

globalThis.BareKit ??= { IPC: { on() {}, off() {}, emit() {} } }
globalThis.Bare ??= { platform: 'posix', on() {} }
