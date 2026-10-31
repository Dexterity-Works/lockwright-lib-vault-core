import b4a from 'b4a'
import fs from 'bare-fs'

/**
 * Appends lines to `path`. Once the file reaches `maxSize` bytes it moves to
 * `<path>.1`, replacing the previous one, and a new file starts, so a trace
 * holds at most about twice `maxSize`. `maxSize` 0 never rotates.
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
        fs.renameSync(path, `${path}.1`)
        fd = fs.openSync(path, 'a')
        size = 0
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
