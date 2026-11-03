'use strict'
// Stand-in for 'udx-native' in network-test child processes: the real module
// wrapped by the public-DHT guard (test/network/child/register.mjs).
const { fileURLToPath } = require('url')
const guard = require(globalThis.__lockwrightGuardPath)
const real = require(fileURLToPath(globalThis.__lockwrightReal['udx-native']))
module.exports = guard.guardUDX(real)
