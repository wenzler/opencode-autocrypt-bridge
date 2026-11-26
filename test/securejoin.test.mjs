import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { createBridge } from '../src/bridge.js'
import {
  decryptMessage,
  decryptMessageWithPassword,
  encryptMime,
  encryptMimeWithPassword,
  keyFingerprint,
} from '../src/crypto.js'
import { loadConfig } from '../src/config.js'
import { armorToBase64, autocryptGossipHeader, autocryptHeader } from '../src/headers.js'
import { buildInnerMime, buildMail, buildPgpMime, extractArmored, parseRawHeaders } from '../src/mime.js'

async function keyPair(email) {
  const pair = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: email.split('@')[0], email }],
    format: 'object',
  })
  const publicB64 = armorToBase64(pair.publicKey.armor())
  return { privateKey: pair.privateKey, publicB64, fingerprint: await keyFingerprint(publicB64) }
}

function harness(contact, options = {}) {
  const cfg = loadConfig({
    address: 'bot@example.org',
    displayName: 'Bridge',
    imapHost: 'imap.example.org',
    imapPassword: 'test',
    smtpHost: 'smtp.example.org',
    smtpPassword: 'test',
    pinnedContact: 'contact@example.net',
    pinnedFingerprint: contact.fingerprint,
    generateKey: false,
    attachmentDir: '/tmp/opencode-autocrypt-bridge-securejoin',
    remoteMode: options.remoteMode || 'securejoin',
  }, {})
  const values = new Map()
  const prompted = []
  const session = {
    id: 'session-1',
    title: 'SecureJoin',
    projectID: 'project-1',
    location: { directory: '/tmp' },
    time: { updated: 10 },
  }
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {
      async create() { return session },
      async get({ sessionID }) {
        if (sessionID !== session.id) throw new Error(`Unknown session ${sessionID}`)
        return session
      },
      async list() { return { data: [session] } },
      async prompt(input) { prompted.push(input.sessionID); return { id: 'user-message' } },
      async wait() {},
      async context() { return [] },
    },
    location: { directory: '/tmp' },
  }
  const sent = []
  const sender = {
    async send(raw, to) { sent.push({ raw: raw.toString('utf8'), to }) },
  }
  return { cfg, ctx, sent, sender, prompted, session }
}

async function buildSymmetricHandshake(cfg, contact, auth, secret, headers) {
  const inner = buildInnerMime({
    text: 'Secure-Join',
    headers: [
      'From: Contact <contact@example.net>',
      'To: <bot@example.org>',
      'Subject: Secure-Join',
      ...headers,
      'Chat-Version: 1.0',
    ],
  })
  const armored = await encryptMimeWithPassword(inner.entity, secret, { privateKey: contact.privateKey })
  const pgp = buildPgpMime(armored)
  return buildMail({
    cfg,
    to: cfg.address,
    subject: 'Chat: Secure-Join',
    messageId: `<sj-${Date.now()}@example.net>`,
    publicB64: contact.publicB64,
    contentType: pgp.contentType,
    body: pgp.body,
    from: 'Contact <contact@example.net>',
    autocryptAddress: 'contact@example.net',
  })
}

async function buildAsymmetricHandshake(cfg, contact, bot, auth, headers) {
  const inner = buildInnerMime({
    text: 'Secure-Join',
    headers: [
      'From: Contact <contact@example.net>',
      'To: <bot@example.org>',
      'Subject: Secure-Join',
      ...headers,
      'Chat-Version: 1.0',
    ],
  })
  const armored = await encryptMime(inner.entity, {
    privateKey: contact.privateKey,
    publicB64: contact.publicB64,
  }, [bot.publicB64])
  const pgp = buildPgpMime(armored)
  return buildMail({
    cfg,
    to: cfg.address,
    subject: 'Chat: Secure-Join',
    messageId: `<sj-auth-${Date.now()}@example.net>`,
    publicB64: contact.publicB64,
    contentType: pgp.contentType,
    body: pgp.body,
    from: 'Contact <contact@example.net>',
    autocryptAddress: 'contact@example.net',
  })
}

test('SecureJoin v3 verifies the pinned key and then rejects plaintext', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const h = harness(contact)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: {
      privateKey: bot.privateKey,
      publicB64: bot.publicB64,
      publicArmored: bot.privateKey.toPublic().armor(),
    },
    sender: h.sender,
    log: () => {},
  })

  const invite = await bridge.getSecureJoinQr()
  assert.match(invite.uri, /^OPENPGP4FPR:[0-9A-F]{40}#/)
  assert.ok(invite.uri.startsWith(`OPENPGP4FPR:${bot.fingerprint}#`))
  assert.equal(invite.address, 'bot@example.org')
  assert.equal(invite.pinnedContact, 'contact@example.net')
  const params = new URLSearchParams(invite.uri.split('#')[1])
  const auth = params.get('s')
  assert.ok(auth && auth.length > 10)
  assert.equal(params.get('a'), 'bot@example.org')
  assert.equal(params.get('v'), '3')
  const secret = `securejoin/${bot.fingerprint}/${auth}`

  await bridge.process(await buildSymmetricHandshake(h.cfg, contact, auth, secret, [
    'Secure-Join: vc-request-pubkey',
    `Secure-Join-Auth: ${auth}`,
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
  ]))
  assert.equal(h.sent.length, 1)
  const pubkeyHeaders = parseRawHeaders(Buffer.from(h.sent[0].raw))
  assert.equal(pubkeyHeaders.get('secure-join'), 'vc-pubkey')
  const pubkeyEntity = await decryptMessageWithPassword(extractArmored(Buffer.from(h.sent[0].raw)), secret)
  const pubkeyInner = parseRawHeaders(pubkeyEntity)
  assert.equal(pubkeyInner.get('secure-join'), 'vc-pubkey')
  assert.match(pubkeyInner.get('autocrypt'), /keydata=/)

  await bridge.process(await buildAsymmetricHandshake(h.cfg, contact, bot, auth, [
    'Secure-Join: vc-request-with-auth',
    `Secure-Join-Auth: ${auth}`,
    `Secure-Join-Fingerprint: ${contact.fingerprint}`,
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    `Autocrypt-Gossip: ${autocryptGossipHeader('bot@example.org', bot.publicB64)}`,
  ]))
  assert.equal(h.sent.length, 2)
  const confirm = parseRawHeaders(Buffer.from(h.sent[1].raw))
  assert.equal(confirm.get('secure-join'), 'vc-contact-confirm')
  const confirmEntity = await decryptMessage(extractArmored(Buffer.from(h.sent[1].raw)), {
    privateKey: contact.privateKey,
  }, bot.publicB64)
  const confirmInner = parseRawHeaders(confirmEntity.data)
  assert.equal(confirmInner.get('secure-join'), 'vc-contact-confirm')
  assert.match(confirmInner.get('autocrypt-gossip'), /keydata=/)

  const status = await bridge.getStatus()
  assert.equal(status.remoteMode, 'securejoin')
  assert.equal(status.selfFingerprint, bot.fingerprint)
  assert.equal(status.secureJoin.status, 'verified')
  assert.equal(status.verified, true)
  assert.equal(status.learnedFingerprint, contact.fingerprint)

  const plaintext = Buffer.from([
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    'Subject: after verification',
    'Message-ID: <after-verification@example.net>',
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    'this plaintext must be ignored',
    '',
  ].join('\r\n'))
  await bridge.process(plaintext)
  assert.deepEqual(h.prompted, [])
  assert.equal(h.sent.length, 2)
})

test('Autocrypt mode keeps the legacy request and does not expose SecureJoin', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const h = harness(contact, { remoteMode: 'autocrypt' })
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: {
      privateKey: bot.privateKey,
      publicB64: bot.publicB64,
      publicArmored: bot.privateKey.toPublic().armor(),
    },
    sender: h.sender,
    log: () => {},
  })

  await assert.rejects(() => bridge.getSecureJoinQr(), /only available in SecureJoin remote mode/)
  await bridge.startHandshake()
  assert.equal(h.sent.length, 1)
  assert.equal(parseRawHeaders(Buffer.from(h.sent[0].raw)).get('x-opencode-handshake'), 'autocrypt-request')
  assert.equal((await bridge.getStatus()).remoteMode, 'autocrypt')
})
