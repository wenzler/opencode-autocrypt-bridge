import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import * as openpgp from 'openpgp'
import { createBridge } from '../src/bridge.js'
import { keyFingerprint } from '../src/crypto.js'
import { loadConfig } from '../src/config.js'
import { armorToBase64, autocryptHeader } from '../src/headers.js'

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
    fingerprint: await keyFingerprint(armorToBase64(pair.publicKey.armor())),
  }
}

function commandMail(contact) {
  return Buffer.from([
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    'Subject: Outbox test',
    `Date: ${new Date().toUTCString()}`,
    'Message-ID: <outbox-prompt@example.net>',
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    '!help',
    '',
  ].join('\r\n'))
}

test('failed SMTP sends are queued and retried from persisted state', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const root = await mkdtemp(path.join(os.tmpdir(), 'opencode-ac-outbox-'))
  const cfg = loadConfig({
    address: 'bot@example.org',
    displayName: 'Bridge',
    imapHost: 'imap.example.org',
    imapPassword: 'test',
    smtpHost: 'smtp.example.org',
    smtpPassword: 'test',
    pinnedContact: 'contact@example.net',
    pinnedFingerprint: contact.fingerprint,
    remoteMode: 'autocrypt',
    generateKey: false,
    attachmentDir: path.join(root, 'attachments'),
  }, {})

  const values = new Map()
  values.set('autocrypt.state', {
    sessions: { 'contact@example.net': 'session-1' },
    peers: { 'contact@example.net': { keydata: contact.publicB64 } },
    seen: [],
    threads: {},
    sessionContacts: { 'session-1': 'contact@example.net' },
    meta: {},
    handshake: { established: true, verified: true },
    watches: {},
    pending: {},
    questions: {},
    sent: {},
    outbox: [],
  })
  const session = {
    id: 'session-1',
    title: 'Outbox test',
    projectID: 'project-1',
    location: { directory: root },
    time: { updated: 10 },
  }
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {
      async get({ sessionID }) {
        if (sessionID !== session.id) throw new Error(`Unknown session ${sessionID}`)
        return session
      },
      async list() { return { data: [session] } },
      async create() { return session },
      async prompt() { return { id: 'user-message' } },
      async wait() {},
      async context() { return [] },
    },
    event: {
      subscribe() { return (async function* () {})() },
    },
    location: { directory: root },
  }

  const sent = []
  let fail = true
  const sender = {
    async send(raw, to) {
      if (fail) {
        fail = false
        throw new Error('SMTP temporarily unavailable')
      }
      sent.push({ raw: raw.toString('utf8'), to })
    },
  }
  const bridge = await createBridge(ctx, cfg, { identity: bot, sender, log: () => {} })

  await bridge.process(commandMail(contact))
  assert.equal(sent.length, 0, 'failed send is not counted as delivered')
  const queuedStatus = await bridge.getStatus()
  assert.equal(queuedStatus.queuedReplies, 1)
  assert.ok(queuedStatus.nextReplyRetryAt > Date.now())

  const persisted = values.get('autocrypt.state').outbox
  assert.equal(persisted.length, 1)
  assert.equal(persisted[0].to, 'contact@example.net')
  assert.ok(persisted[0].raw)

  await bridge.flushOutbox(true)
  assert.equal(sent.length, 1, 'queued reply is retried')
  assert.equal(sent[0].to, 'contact@example.net')
  assert.match(sent[0].raw, /^From:/)
  assert.equal((await bridge.getStatus()).queuedReplies, 0)
  assert.equal(values.get('autocrypt.state').outbox.length, 0)
})

function outboxState(overrides = {}) {
  return {
    sessions: {}, peers: {}, seen: [], threads: {}, sessionContacts: {}, meta: {},
    handshake: {}, watches: {}, pending: {}, questions: {}, sent: {}, outbox: [],
    ...overrides,
  }
}

test('a pinned-contact trust change discards queued replies', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const cfg = loadConfig({
    address: 'bot@example.org', displayName: 'Bridge', imapHost: 'imap.example.org', imapPassword: 't',
    smtpHost: 'smtp.example.org', smtpPassword: 't', pinnedContact: 'contact@example.net',
    pinnedFingerprint: contact.fingerprint, remoteMode: 'autocrypt', generateKey: false,
  }, {})
  const values = new Map()
  values.set('autocrypt.state', outboxState({
    outbox: [{
      id: 'stale', to: 'contact@example.net', messageId: '<stale@example.net>',
      raw: Buffer.from('From: bot@example.org').toString('base64'),
      createdAt: Date.now(), nextAt: 0, encrypted: true,
    }],
    meta: { autocryptOutboxTrust: 'old-contact@example.net|OLD|autocrypt|false' },
  }))
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {},
    event: { subscribe() { return (async function* () {})() } },
    location: { directory: '/tmp' },
  }
  const sent = []
  await createBridge(ctx, cfg, {
    identity: bot,
    sender: { async send(raw, to) { sent.push({ raw, to }) } },
    log: () => {},
  })
  assert.equal(values.get('autocrypt.state').outbox.length, 0, 'stale queued mail is gone')
  assert.deepEqual(sent, [])
})

test('old and oversized queued replies are pruned before retry', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const cfg = loadConfig({
    address: 'bot@example.org', displayName: 'Bridge', imapHost: 'imap.example.org', imapPassword: 't',
    smtpHost: 'smtp.example.org', smtpPassword: 't', pinnedContact: 'contact@example.net',
    pinnedFingerprint: contact.fingerprint, remoteMode: 'autocrypt', generateKey: false,
  }, {})
  const now = Date.now()
  const values = new Map()
  values.set('autocrypt.state', outboxState({
    outbox: [
      {
        id: 'expired', to: 'contact@example.net', messageId: '<expired@example.net>',
        raw: Buffer.from('From: bot@example.org').toString('base64'),
        createdAt: now - 25 * 60 * 60 * 1000, nextAt: 0, encrypted: true,
      },
      {
        id: 'huge', to: 'contact@example.net', messageId: '<huge@example.net>',
        raw: Buffer.alloc(16 * 1024 * 1024).toString('base64'),
        createdAt: now, nextAt: 0, encrypted: true,
      },
      {
        id: 'valid', to: 'contact@example.net', messageId: '<valid@example.net>',
        raw: Buffer.from('From: bot@example.org').toString('base64'),
        createdAt: now, nextAt: 0, encrypted: true,
      },
    ],
    meta: {
      autocryptOutboxTrust: `contact@example.net|${contact.fingerprint}|autocrypt|false`,
    },
  }))
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {},
    event: { subscribe() { return (async function* () {})() } },
    location: { directory: '/tmp' },
  }
  const sent = []
  const bridge = await createBridge(ctx, cfg, {
    identity: bot,
    sender: { async send(raw, to) { sent.push({ raw, to }) } },
    log: () => {},
  })
  await bridge.flushOutbox(true)
  assert.deepEqual(sent.map((entry) => entry.to), ['contact@example.net'])
  assert.equal(values.get('autocrypt.state').outbox.length, 0)
})

test('stale recipients and cleartext bootstrap replies are not retried', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const cfg = loadConfig({
    address: 'bot@example.org', displayName: 'Bridge', imapHost: 'imap.example.org', imapPassword: 't',
    smtpHost: 'smtp.example.org', smtpPassword: 't', pinnedContact: 'contact@example.net',
    pinnedFingerprint: contact.fingerprint, remoteMode: 'autocrypt', generateKey: false,
  }, {})
  const now = Date.now()
  const values = new Map()
  values.set('autocrypt.state', outboxState({
    peers: { 'contact@example.net': { keydata: contact.publicB64 } },
    outbox: [
      {
        id: 'other', to: 'other@example.net', messageId: '<other@example.net>',
        raw: Buffer.from('From: bot@example.org').toString('base64'),
        createdAt: now, nextAt: 0, encrypted: true,
      },
      {
        id: 'clear', to: 'contact@example.net', messageId: '<clear@example.net>',
        raw: Buffer.from('From: bot@example.org').toString('base64'),
        createdAt: now, nextAt: 0, encrypted: false,
      },
    ],
    meta: {
      autocryptOutboxTrust: `contact@example.net|${contact.fingerprint}|autocrypt|false`,
    },
  }))
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {},
    event: { subscribe() { return (async function* () {})() } },
    location: { directory: '/tmp' },
  }
  const sent = []
  const bridge = await createBridge(ctx, cfg, {
    identity: bot,
    sender: { async send(raw, to) { sent.push({ raw, to }) } },
    log: () => {},
  })
  await bridge.flushOutbox(true)
  assert.deepEqual(sent, [])
  assert.equal(values.get('autocrypt.state').outbox.length, 0)
})
