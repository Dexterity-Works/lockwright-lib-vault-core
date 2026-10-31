import { Tracer } from './tracer.js'

// The worklet's trace switch. Off unless the host sets `traceFile` through
// SET_LOG_OPTIONS: while it is off, getTracer() is null and every hook
// below does nothing, so the instances networkCreated hands out are not
// touched. See docs/tracing.md.

const DEFAULT_TRACE_MAX_SIZE = 20_000_000

/** @type {Tracer | null} */
let tracer = null

export const getTracer = () => tracer

/** The harness installs its own tracer per peer; production uses configureTrace. */
export const setTracer = (next) => {
  tracer = next ?? null
}

/**
 * SET_LOG_OPTIONS' trace part. A path starts a trace there (closing any
 * other), null stops it, undefined leaves it alone, like logFile.
 * @param {{ traceFile?: string | null, traceFileMaxSize?: number }} options
 * @returns {Promise<void>}
 */
export const configureTrace = async ({ traceFile, traceFileMaxSize } = {}) => {
  if (traceFile === undefined) return
  tracer?.close()
  tracer = null
  if (typeof traceFile !== 'string' || traceFile.length === 0) return
  // Loaded here, so code that never traces never loads bare-fs for it.
  const { openTraceFile } = await import('./file.js')
  tracer = new Tracer({
    sink: openTraceFile(traceFile, {
      maxSize: traceFileMaxSize || DEFAULT_TRACE_MAX_SIZE
    })
  })
  tracer.record('trace.start', { format: 1 })
}

/** One event, or nothing while tracing is off. */
export const trace = (event, fields) => tracer?.record(event, fields) ?? null

/** networkCreated's hook. A tracer that throws never reaches the caller. */
export const traceCreated = (label, instance) => {
  if (!tracer) return
  try {
    tracer.attach(label, instance)
  } catch (error) {
    tracer.error(`${label}.attach`, error)
  }
}
