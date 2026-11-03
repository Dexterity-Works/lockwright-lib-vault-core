import fs from 'fs'
import os from 'os'
import path from 'path'

import { getForbiddenRoots } from '../../src/worklet/getForbiddenRoots'
import { validateAndSanitizePath } from '../../src/worklet/validateAndSanitizePath'

// Peer storage has to satisfy appDeps.setStoragePath: absolute, no
// dot-directory, outside /tmp, /var and the other forbidden roots. That rules
// out os.tmpdir() and a dot-prefixed worktree, so the harness picks the first
// usable root among LOCKWRIGHT_NET_TMP, $XDG_RUNTIME_DIR (tmpfs, per user)
// and a folder in the home directory.
const underForbiddenRoot = (dir) =>
  getForbiddenRoots().some(
    (root) => dir === root || dir.startsWith(root + path.sep)
  )

let cachedRoot = null

export const storageRoot = () => {
  if (cachedRoot) return cachedRoot
  const candidates = [
    process.env.LOCKWRIGHT_NET_TMP,
    process.env.XDG_RUNTIME_DIR &&
      path.join(process.env.XDG_RUNTIME_DIR, 'lockwright-network-harness'),
    path.join(os.homedir(), 'lockwright-network-harness')
  ].filter(Boolean)
  const reasons = []
  for (const candidate of candidates) {
    try {
      const clean = validateAndSanitizePath(candidate)
      if (underForbiddenRoot(clean)) {
        reasons.push(`${candidate}: under a forbidden root`)
        continue
      }
      fs.mkdirSync(clean, { recursive: true })
      fs.accessSync(clean, fs.constants.W_OK)
      cachedRoot = clean
      return clean
    } catch (error) {
      reasons.push(`${candidate}: ${error.message}`)
    }
  }
  throw new Error(
    `no usable storage root for peers; set LOCKWRIGHT_NET_TMP to an absolute path without dot-directories, outside /tmp and /var. Tried: ${reasons.join('; ')}`
  )
}

/** A fresh directory under the storage root. `prefix` must not contain dots. */
export const mkdtemp = (prefix) =>
  fs.mkdtempSync(path.join(storageRoot(), `${prefix}-`))

export const removeDir = (dir) => {
  fs.rmSync(dir, { recursive: true, force: true })
}
