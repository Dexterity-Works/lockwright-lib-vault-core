// jest setup file for the network project: wraps hyperdht, hyperswarm and
// udx-native so nothing in the test, or in the code under test, can reach the
// public DHT. The mocks are the real modules behind a constructor check.
const guard = require('./guard.cjs')

jest.mock('hyperdht', () => guard.guardDHT(jest.requireActual('hyperdht')))
jest.mock('hyperswarm', () =>
  guard.guardSwarm(jest.requireActual('hyperswarm'))
)
jest.mock('udx-native', () => guard.guardUDX(jest.requireActual('udx-native')))
