import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { createBridge } from '../src/bridge.js'
import { loadConfig } from '../src/config.js'
import { armorToBase64 } from '../src/headers.js'

async function keyPair(email) {
  const pair = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: email.split('@')[0], email }],
    format: 'object',
  })
  return {
    privateKey: pair.privateKey,
    publicB64: armorToBase64(pair.publicKey.armor()),
  }
}

function mailConfig() {
  return loadConfig({
    address: 'bot@example.org',
    displayName: 'Bridge',
    imapHost: 'imap.example.org',
    imapPassword: 'test',
    smtpHost: 'smtp.example.org',
    smtpPassword: 'test',
    pinnedContact: 'contact@example.net',
    pinnedFingerprint: '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE',
    generateKey: false,
  }, {})
}

function fakeContext(values) {
  return {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {},
    event: { subscribe() { return (async function* () {})() } },
    location: { directory: '/tmp' },
  }
}

async function waitFor(check, ms = 2000) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    if (await check()) return
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  throw new Error('timed out waiting for lease state')
}

test('only the bridge holding the shared mail lease runs IMAP', async () => {
  const identity = await keyPair('bot@example.org')
  const values = new Map()
  const ctx = fakeContext(values)
  const cfg = mailConfig()
  const imapStarts = []
  const makeBridge = (name) => createBridge(ctx, cfg, {
    identity,
    log: () => {},
    sender: { async send() {} },
    startImap: () => {
      imapStarts.push(name)
      return new Promise(() => {})
    },
    leaseConfirmMs: 5,
    leaseHeartbeatMs: 1000,
  })

  const first = await makeBridge('first')
  assert.equal(await first.start(), true)
  assert.equal((await first.getStatus()).running, true)
  assert.deepEqual(imapStarts, ['first'])

  const second = await makeBridge('second')
  assert.equal(await second.start(), false)
  assert.equal((await second.getStatus()).running, false)
  assert.deepEqual(imapStarts, ['first'])
  assert.match((await second.getStatus()).lastError, /Another Autocrypt bridge/)
  await assert.rejects(() => second.rescanInbox(), /Another Autocrypt bridge/)
  assert.equal(await second.process('unreadable'), false)

  await first.stop()
  assert.equal(values.get('autocrypt.bridge.lease').owner, '')

  assert.equal(await second.start(), true)
  assert.equal((await second.getStatus()).running, true)
  assert.deepEqual(imapStarts, ['first', 'second'])
  await second.stop()
})

test('a bridge stops mailing when another process takes over its lease', async () => {
  const identity = await keyPair('bot@example.org')
  const values = new Map()
  const ctx = fakeContext(values)
  let aborted = false
  const bridge = await createBridge(ctx, mailConfig(), {
    identity,
    log: () => {},
    sender: { async send() {} },
    startImap: (_cfg, _store, _handle, signal) => {
      signal.addEventListener('abort', () => { aborted = true })
      return new Promise(() => {})
    },
    leaseConfirmMs: 5,
    leaseHeartbeatMs: 20,
  })
  assert.equal(await bridge.start(), true)

  const takeover = { owner: 'other-process', renewedAt: Date.now() }
  values.set('autocrypt.bridge.lease', takeover)

  await waitFor(async () => !(await bridge.getStatus()).running)
  await waitFor(() => aborted)
  assert.deepEqual(values.get('autocrypt.bridge.lease'), takeover)
  assert.match((await bridge.getStatus()).lastError, /Another Autocrypt bridge/)
  await bridge.stop()
})
