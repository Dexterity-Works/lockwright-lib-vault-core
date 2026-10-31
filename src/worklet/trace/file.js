import b4a from 'b4a'
import fs from 'bare-fs'

/**
 * Appends lines to `path`. Once the file reaches `maxSize` bytes it moves to
 * `<path>.1`, replacing the previous one, and a new file starts, so a trace
 * holds at most about twice `maxSize`. `maxSize` 0 never rotates. If the
 * rotation fails the trace stops writing.
 * @param {string} path
 * @param {{ maxSize?: number }} [options]
 */
export const openTraceFile = (path, { maxSize = 0 } = {}) => {
  let fd = fs.openSync(path, 'a')
  let size = fs.fstatSync(fd).size
  return {
    write(line) {
      if (fd === -1) return
      if (maxSize > 0 && size >= maxSize) {
        fs.closeSync(fd)
        // Forgotten at once: the number may soon belong to another file.
        fd = -1
        try {
          fs.renameSync(path, `${path}.1`)
          fd = fs.openSync(path, 'a')
          size = 0
        } catch {
          // A trace that cannot rotate stops; it never throws into the app.
          return
        }
      }
      fs.writeSync(fd, line)
      size += b4a.byteLength(line)
    },
    close() {
      if (fd === -1) return
      fs.closeSync(fd)
      fd = -1
    }
  }
}
