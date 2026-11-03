// Stand-in for bare-file-logger and bare-system-logger under Node: their
// bindings only load under Bare. WorkletLogger constructs them only when the
// host opts in, which the harness never does.
class NoopLogger {
  debug() {}
  info() {}
  warn() {}
  error() {}
  close() {}
}
module.exports = NoopLogger
