'use strict'
// Stand-in for 'hyperswarm' in network-test child processes: the real module
// wrapped by the public-DHT guard (test/network/child/register.mjs).
const { fileURLToPath } = require('url')
const guard = require(globalThis.__lockwrightGuardPath)
const real = require(fileURLToPath(globalThis.__lockwrightReal['hyperswarm']))
module.exports = guard.guardSwarm(real)
