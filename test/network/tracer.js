import { openTraceFile } from '../../src/worklet/trace/file.js'
import { Tracer as WorkletTracer } from '../../src/worklet/trace/tracer.js'

export { classify, short } from '../../src/worklet/trace/tracer.js'

/**
 * One peer's trace: the worklet's own tracer (src/worklet/trace), writing
 * JSONL to `file` and keeping its events in memory for assertions. The
 * peer installs it in its module copy, so it sees what an app with a
 * traceFile would record.
 */
export class Tracer extends WorkletTracer {
  /**
   * @param {{ peer: string, file: string, relayAddresses?: Set<string>, onEvent?: Function, sampleInterval?: number }} options
   */
  constructor({ peer, file, relayAddresses, onEvent, sampleInterval }) {
    super({
      peer,
      sink: openTraceFile(file),
      relayAddresses,
      onEvent,
      keepEvents: true,
      sampleInterval
    })
    this.file = file
  }
}
