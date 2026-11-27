import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { createBridge } from '../src/bridge.js'
import { loadConfig } from '../src/config.js'
import { keyFingerprint } from '../src/crypto.js'
import { armorToBase64, autocryptHeader } from '../src/headers.js'
import { rescanMailbox, startImap } from '../src/mail.js'

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

function mailConfig(overrides = {}) {
  return loadConfig({
    address: 'bot@example.org',
    displayName: 'Bridge',
    imapHost: 'imap.example.org',
    imapPassword: 'test',
    smtpHost: 'smtp.example.org',
    smtpPassword: 'test',
    pinnedContact: 'contact@example.net',
    pinnedFingerprint: '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE',
    ...overrides,
  }, {})
}

function fakeImapClient({ deleted = [], uid = 7 } = {}) {
  return {
    usable: true,
    idling: false,
    mailbox: null,
    capabilities: { has: () => true },
    on() {},
    async connect() {},
    async mailboxOpen() {
      this.mailbox = { uidValidity: 42, uidNext: 20, exists: 1 }
    },
    async *fetch() {
      yield { uid, size: 128 }
    },
    async fetchOne() {
      return { source: Buffer.from('message source') }
    },
    async noop() {},
    async idle() {},
    async messageDelete(uid) {
      deleted.push(uid)
    },
    async close() {},
  }
}

test('a failed rescan keeps the checkpoint behind the message and leaves it in the mailbox', async () => {
  const cfg = mailConfig()
  cfg.imap.deleteAfterRead = true
  const store = new Map()
  const deleted = []
  const attempts = []
  const client = fakeImapClient({ deleted })
  const result = await rescanMailbox(cfg, store, async () => {
    attempts.push(1)
    return false
  }, () => {}, undefined, () => client)
  assert.equal(result.processed, 0)
  assert.equal(attempts.length, 1)
  assert.equal(store.has('imap:INBOX'), false)
  assert.deepEqual(deleted, [])
})

test('a successful rescan advances the checkpoint and expunges when configured', async () => {
  const cfg = mailConfig()
  cfg.imap.deleteAfterRead = true
  const store = new Map()
  const deleted = []
  const client = fakeImapClient({ deleted })
  const result = await rescanMailbox(cfg, store, async () => true, () => {}, undefined, () => client)
  assert.equal(result.processed, 1)
  assert.deepEqual(store.get('imap:INBOX'), { validity: '42', uid: 7 })
  assert.deepEqual(deleted, [7])
})

test('the live IMAP loop retries a failed message instead of deleting it', async () => {
  const cfg = mailConfig()
  cfg.imap.deleteAfterRead = true
  cfg.imap.pollIntervalMs = 1
  const store = new Map()
  const deleted = []
  const controller = new AbortController()
  let calls = 0
  const client = fakeImapClient({ deleted, uid: 25 })
  await startImap(cfg, store, async () => {
    calls += 1
    controller.abort()
    return false
  }, controller.signal, () => {}, () => client)
  assert.equal(calls, 1)
  assert.deepEqual(store.get('imap:INBOX'), { validity: '42', uid: 19 })
  assert.deepEqual(deleted, [])
})

test('a quarantined rescan advances the checkpoint but keeps the mail', async () => {
  const cfg = mailConfig()
  cfg.imap.deleteAfterRead = true
  const store = new Map()
  const deleted = []
  const client = fakeImapClient({ deleted })
  const result = await rescanMailbox(cfg, store, async () => 'skip', () => {}, undefined, () => client)
  assert.equal(result.processed, 0)
  assert.deepEqual(store.get('imap:INBOX'), { validity: '42', uid: 7 })
  assert.deepEqual(deleted, [])
})

async function waitFor(promise, ms = 2000) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms) }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

test('start and stop emit resolved status objects, not promises', async () => {
  const identity = await keyPair('bot@example.org')
  const cfg = mailConfig()
  cfg.generateKey = false
  const values = new Map()
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {},
    event: { subscribe() { return (async function* () {})() } },
    location: { directory: '/tmp' },
  }
  let resolveStarted
  let resolveStopped
  const started = new Promise((resolve) => { resolveStarted = resolve })
  const stopped = new Promise((resolve) => { resolveStopped = resolve })
  const statuses = []
  const bridge = await createBridge(ctx, cfg, {
    identity,
    log: () => {},
    sender: { async send() {} },
    startImap: async () => {},
    onStatus(status) {
      statuses.push(status)
      if (status?.running === true) resolveStarted(status)
      if (statuses.length > 1 && status?.running === false) resolveStopped(status)
    },
  })
  bridge.start()
  const startStatus = await waitFor(started)
  assert.equal(typeof startStatus.then, 'undefined')
  assert.equal(startStatus.running, true)
  bridge.stop()
  const stopStatus = await waitFor(stopped)
  assert.equal(typeof stopStatus.then, 'undefined')
  assert.equal(stopStatus.running, false)
})

test('a malformed message is consumed instead of blocking the mailbox', async () => {
  const identity = await keyPair('bot@example.org')
  const cfg = mailConfig({ generateKey: false })
  const values = new Map()
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {},
    event: { subscribe() { return (async function* () {})() } },
    location: { directory: '/tmp' },
  }
  const bridge = await createBridge(ctx, cfg, {
    identity,
    log: () => {},
    sender: { async send() {} },
    startImap: async () => {},
  })
  assert.equal(await bridge.process(Buffer.from('not a mail at all')), true)
})

test('repeated inbound failures are bounded and quarantined', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const cfg = mailConfig({
    remoteMode: 'autocrypt',
    generateKey: false,
    pinnedContactKey: contact.publicB64,
  })
  cfg.pinned.fingerprint = await keyFingerprint(contact.publicB64)
  const values = new Map()
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {
      async get({ sessionID }) { return { id: sessionID, title: 'Quarantine test' } },
      async create() { return { id: 'session-1' } },
      async list() { return { data: [] } },
    },
    event: { subscribe() { return (async function* () {})() } },
    location: { directory: '/tmp' },
  }
  const sent = []
  const bridge = await createBridge(ctx, cfg, {
    identity: bot,
    log: () => {},
    sender: { async send(raw, to) { sent.push({ raw, to }) } },
    encryptMime: async () => { throw new Error('broken encryption key') },
  })
  const raw = Buffer.from([
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    'Subject: Retry test',
    `Date: ${new Date().toUTCString()}`,
    'Message-ID: <quarantine-test@example.net>',
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    '!sessions',
    '',
  ].join('\r\n'))

  const id = '<quarantine-test@example.net>'
  assert.equal(await bridge.process(raw), false)
  values.get('autocrypt.state').retries[id].nextAt = 0
  assert.equal(await bridge.process(raw), false)
  values.get('autocrypt.state').retries[id].nextAt = 0
  assert.equal(await bridge.process(raw), 'skip')
  const status = await bridge.getStatus()
  assert.equal(status.quarantinedInbound, 1)
  assert.match(status.lastInboundWarning, /Quarantined message/)
  assert.deepEqual(sent, [])
})

test('an encryption failure never falls back to cleartext', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const cfg = mailConfig({
    remoteMode: 'autocrypt',
    generateKey: false,
    pinnedContactKey: contact.publicB64,
  })
  cfg.pinned.fingerprint = await keyFingerprint(contact.publicB64)
  const values = new Map()
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {
      async get({ sessionID }) {
        if (sessionID !== 'session-1') throw new Error(`Unknown session ${sessionID}`)
        return { id: sessionID, title: 'Encryption test' }
      },
      async create() { return { id: 'session-1', title: 'Encryption test' } },
      async list() { return { data: [] } },
    },
    event: { subscribe() { return (async function* () {})() } },
    location: { directory: '/tmp' },
  }
  const sent = []
  const logs = []
  const bridge = await createBridge(ctx, cfg, {
    identity: bot,
    log: (message) => logs.push(message),
    sender: { async send(raw, to) { sent.push({ raw, to }) } },
    encryptMime: async () => { throw new Error('broken encryption key') },
  })
  const raw = Buffer.from([
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    'Subject: Encryption failure',
    `Date: ${new Date().toUTCString()}`,
    'Message-ID: <encryption-failure@example.net>',
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    '!sessions',
    '',
  ].join('\r\n'))
  assert.equal(await bridge.process(raw), false)
  assert.deepEqual(sent, [])
  assert.match(logs.join('\n'), /Could not encrypt.*broken encryption key/)
})
