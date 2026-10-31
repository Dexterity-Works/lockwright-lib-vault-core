# Sync tracing

The worklet can write a trace of what sync and connections do: every Hyperswarm, Autopass and DHT it builds, each connection attempt and why it failed, which connections opened and by which path, sampled swarm and DHT counters, epoch status changes, the record migration, pairing, and the kick steps (writer and device row removal, epoch rotation, the personal-swarm notice). It is off unless the app turns it on.

## Turning it on in an app

Pass `traceFile` to `setLogOptions`, the call that already sets `logFile`:

```js
await client.setLogOptions({
  traceFile: '/path/to/laptop.trace.jsonl', // absolute path
  traceFileMaxSize: 20_000_000 // optional, bytes, default 20 MB
})
```

- A path starts a trace there; calling again with another path moves it.
- `traceFile: null` stops it.
- Leaving `traceFile` out leaves tracing as it was. An app that never passes it gets exactly the current behaviour: no tracer is attached and no builder options change.

Put the file next to the app's log file, in the app's own data or logs folder. Name it after the device (`laptop.trace.jsonl`, `phone.trace.jsonl`): the report names each device after its file. Once the file reaches `traceFileMaxSize` it moves to `<file>.1`, replacing the previous one, and a new file starts.

Turn the trace on before unlocking, so it sees the master vault, the active vault and the personal swarm as they are built.

## What the trace holds

One JSON object per line: `t` (ms since the trace started, monotonic), `wall` (the device's clock), `event`, `label` (`master`, `vault`, `pairer`, `personalSwarm`, `personalSend`, `sharedDHT`) and the event's fields.

It holds key prefixes (8 characters), peer IP:port, topic and autobase lengths, error codes and timings. It never holds secrets, record contents, vault or item names, passwords, invite codes or full keys. Fields go through the logger's `redact()`. In any string, an absolute path is cut to its last component, a UUID to its first 8 characters, and a key-length hex, base64 or z32 run is replaced. The network tests sweep the trace and its report for all of these.

The tracer only listens: it adds no `error` listener to a vault or a connection, so an error that would stop the app still does. A trace file that cannot rotate stops writing.

`relayed` needs the relay's address. The tracer learns it at runtime: the swarm's relay keys come from its `relayThrough` (the app's blind relays), and the address a dial to one of those keys opens on is a relay address. A connection that rides another stream's address when that stream is not a known relay is `unknown`, never `direct`.

The main events:

| event | when |
|---|---|
| `conn.attempt` | an outgoing connect: `remote`; `relayed` is true when a relay key was passed, false for none, null when a function picks it |
| `conn.fail` | an attempt that closed without opening: `code` (`PEER_NOT_FOUND`, `HOLEPUNCH_ABORTED`, ...), `ms` |
| `conn.open`, `conn.upgrade`, `conn.close` | `path` is `direct`, `holepunched`, `relayed` or `unknown`; `remoteAddress`; `conn.close` has the error `code` |
| `relay.open` | a connection to a blind relay opened; connections on its `address` are `relayed` |
| `swarm.stats`, `dht.stats`, `swarm.peers` | counters, sampled every 500 ms and written only when they change |
| `epoch.status` | the active vault's epoch status, when it changes |
| `migration.start`, `.skipped`, `.deferred`, `.resume`, `.finish`, `.error` | the record migration; `skippedAtEpoch` is an epoch prefix |
| `pairing.invite`, `.pair`, `.paired`, `.fail`, `.cancel` | pairing |
| `writer.remove`, `device.remove`, `epoch.ensure`, `personal.send` | the kick steps |

## Building the report

```sh
node scripts/trace-report.mjs laptop.trace.jsonl phone.trace.jsonl -o report.html
```

The result is one self-contained `report.html`: no server, no network requests, it opens from a file. It shows a failure banner, a network diagram (devices, DHT nodes, links coloured by path as connections open, dashed for failing attempts), one row per device on a shared time axis with steps, attempts, connections, epoch and migration events and faults as bands, and a filterable event table. Wheel to zoom, drag to scroll.

Traces from several devices merge by wall clock. Device clocks are not corrected: the report shows the offsets it can estimate from both ends of the same connection.

Other inputs, all optional:

- `--topology f`: `{ "nodes": [{ "id", "label", "kind" }], "links": [{ "from", "to", "label" }] }`. A node whose `id` is a device name is that device.
- `--net f`: JSONL network records. Records with `from`, `to` and `drops` label that link; all are listed.
- `--asserts f`: `[{ "name", "pass", "message", "matched": [{ "peer", "event", "wall" }] }]`.
- `--failure text`, `--title text`.
- A harness `timeline.json` works as a trace too.

## In the network tests

Each harness peer installs the worklet's tracer in its own module copy, so the tests record what an app with a `traceFile` would. A failed test, or any test with `LOCKWRIGHT_NET_KEEP=1`, leaves `timeline.json`, `timeline.txt` and `report.html` under `test-artifacts/<test name>/` and prints their paths. `test/network/fixtures/partition.network.js` fails on purpose and makes a sample report.
