import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { simpleParser } from 'mailparser'
import { createBridge } from '../src/bridge.js'
import {
  decryptMessage,
  decryptMessageWithPasswordDetailed,
  encryptMime,
  encryptMimeWithPassword,
  keyFingerprint,
} from '../src/crypto.js'
import { loadConfig } from '../src/config.js'
import { armorToBase64, autocryptGossipHeader, autocryptHeader } from '../src/headers.js'
import { buildInnerMime, buildMail, buildPgpMime, extractArmored, parseRawHeaders } from '../src/mime.js'

const AUTH = 'NJFZBXGwoQh6B_kDQlJrj2nP'
const secretFor = (fingerprint, auth = AUTH) => `securejoin/${fingerprint}/${auth}`
const inviteFor = (contact, auth = AUTH) => (
  `OPENPGP4FPR:${contact.fingerprint}#a=contact%40example.net&n=Contact&s=${auth}&v=3`
)

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
    inviteUrl: options.inviteUrl || '',
    secureJoinAuth: options.secureJoinAuth || '',
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

async function makeBridge(contact, options = {}) {
  const h = harness(contact, options)
  const bot = await keyPair('bot@example.org')
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: {
      privateKey: bot.privateKey,
      publicB64: bot.publicB64,
      publicArmored: bot.privateKey.toPublic().armor(),
    },
    sender: h.sender,
    log: () => {},
  })
  return { ...h, bot, bridge }
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
    contentType: pgp.contentType,
    body: pgp.body,
    from: 'Contact <contact@example.net>',
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

test('symmetric SecureJoin messages use salted S2K for Delta Chat compatibility', async () => {
  const contact = await keyPair('contact@example.net')
  const secret = secretFor(contact.fingerprint)
  const inner = buildInnerMime({
    text: 'Secure-Join',
    headers: [
      'From: Contact <contact@example.net>',
      'To: <bot@example.org>',
      'Subject: Secure-Join',
      'Secure-Join: vc-pubkey',
      `Secure-Join-Auth: ${AUTH}`,
      'Chat-Version: 1.0',
    ],
  })
  const armored = await encryptMimeWithPassword(inner.entity, secret, { privateKey: contact.privateKey })
  const parsed = await openpgp.readMessage({ armoredMessage: armored })
  const skesk = parsed.packets.find((packet) => packet.constructor === openpgp.SymEncryptedSessionKeyPacket)
  assert.ok(skesk)
  assert.equal(skesk.s2k.type, 'salted')
  const opened = await openpgp.decrypt({
    message: parsed,
    passwords: [secret],
    verificationKeys: [contact.privateKey.toPublic()],
    expectSigned: true,
    format: 'binary',
  })
  await Promise.all(opened.signatures.map((signature) => signature.verified))
  assert.match(Buffer.from(opened.data).toString('utf8'), /Secure-Join: vc-pubkey/)
})

test('SecureJoin joins the contact invite, verifies the pin and then rejects plaintext', async () => {
  const contact = await keyPair('contact@example.net')
  const h = await makeBridge(contact, { inviteUrl: inviteFor(contact) })
  const secret = secretFor(contact.fingerprint)

  const started = await h.bridge.startSecureJoin()
  assert.equal(started.remoteMode, 'securejoin')
  assert.equal(started.secureJoin.status, 'request-sent')
  assert.equal(started.secureJoin.address, 'contact@example.net')
  assert.equal(started.secureJoin.fingerprint, contact.fingerprint)
  assert.equal(started.secureJoin.hasAuth, true)
  assert.equal(started.established, false)
  assert.equal(started.verified, false)
  assert.equal(h.sent.length, 1)
  assert.equal(h.sent[0].to, 'contact@example.net')
  const requestHeaders = parseRawHeaders(Buffer.from(h.sent[0].raw))
  assert.equal(requestHeaders.get('secure-join'), 'vc-request-pubkey')
  assert.equal(requestHeaders.get('secure-join-auth'), AUTH)
  assert.equal(requestHeaders.get('autocrypt'), undefined)
  const request = await decryptMessageWithPasswordDetailed(extractArmored(Buffer.from(h.sent[0].raw)), secret)
  assert.equal(request.signatureVerified, false)
  const requestInner = parseRawHeaders(request.data)
  assert.equal(requestInner.get('secure-join'), 'vc-request-pubkey')
  assert.equal(requestInner.get('secure-join-auth'), AUTH)

  await h.bridge.process(await buildSymmetricHandshake(h.cfg, contact, AUTH, secret, [
    'Secure-Join: vc-pubkey',
    `Secure-Join-Auth: ${AUTH}`,
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
  ]))
  assert.equal(h.sent.length, 2)
  const authHeaders = parseRawHeaders(Buffer.from(h.sent[1].raw))
  assert.equal(authHeaders.get('secure-join'), 'vc-request-with-auth')
  assert.equal(authHeaders.get('secure-join-auth'), AUTH)
  const authEntity = await decryptMessage(
    extractArmored(Buffer.from(h.sent[1].raw)),
    { privateKey: contact.privateKey },
    h.bot.publicB64,
  )
  assert.equal(authEntity.signatureVerified, true)
  const authInner = parseRawHeaders(authEntity.data)
  assert.equal(authInner.get('secure-join'), 'vc-request-with-auth')
  assert.equal(authInner.get('secure-join-auth'), AUTH)
  assert.equal(authInner.get('secure-join-fingerprint'), h.bot.fingerprint)
  assert.match(authInner.get('autocrypt'), /keydata=/)
  const flatten = (value) => String(value).replace(/\s+/g, '')
  assert.equal(
    flatten(authInner.get('autocrypt-gossip')),
    flatten(autocryptGossipHeader('contact@example.net', contact.publicB64)),
  )
  const beforeConfirm = await h.bridge.getStatus()
  assert.equal(beforeConfirm.secureJoin.status, 'auth-sent')
  assert.equal(beforeConfirm.established, false)
  assert.equal(beforeConfirm.verified, false)

  await h.bridge.process(await buildAsymmetricHandshake(h.cfg, contact, h.bot, AUTH, [
    'Secure-Join: vc-contact-confirm',
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    `Autocrypt-Gossip: ${autocryptGossipHeader('bot@example.org', h.bot.publicB64)}`,
  ]))

  const status = await h.bridge.getStatus()
  assert.equal(status.selfFingerprint, h.bot.fingerprint)
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
  await h.bridge.process(plaintext)
  assert.deepEqual(h.prompted, [])
  assert.equal(h.sent.length, 3, 'verification sends a one-time welcome mail')
  const welcome = await decryptMessage(
    extractArmored(Buffer.from(h.sent[2].raw)),
    { privateKey: contact.privateKey },
    h.bot.publicB64,
  )
  const welcomeText = String((await simpleParser(welcome.data)).text || '')
  assert.match(welcomeText, /Key confirmed for contact@example\.net/)
  assert.match(welcomeText, /!sessions/)
})

test('all SecureJoin fields can be entered manually without an invite URL', async () => {
  const contact = await keyPair('contact@example.net')
  const h = await makeBridge(contact, { secureJoinAuth: AUTH })
  const status = await h.bridge.startSecureJoin()
  assert.equal(status.secureJoin.status, 'request-sent')
  assert.equal(status.secureJoin.hasAuth, true)
  assert.equal(h.sent.length, 1)
  assert.equal(parseRawHeaders(Buffer.from(h.sent[0].raw)).get('secure-join-auth'), AUTH)
})

test('SecureJoin ignores messages before verification and rejects the wrong key or auth', async () => {
  const contact = await keyPair('contact@example.net')
  const h = await makeBridge(contact, { inviteUrl: inviteFor(contact, AUTH), secureJoinAuth: 'DIFFERENTAUTHCODE1234' })
  await h.bridge.startSecureJoin()
  assert.equal(h.sent.length, 1)

  // A normal encrypted prompt must not drive OpenCode before verification.
  await h.bridge.process(await buildAsymmetricHandshake(h.cfg, contact, h.bot, '', [
    'Subject: premature prompt',
  ]))
  assert.deepEqual(h.prompted, [])

  // The pinned key is required even when the auth code and address are right.
  const wrongKey = await keyPair('contact@example.net')
  await h.bridge.process(await buildSymmetricHandshake(h.cfg, wrongKey, 'DIFFERENTAUTHCODE1234', secretFor(contact.fingerprint, 'DIFFERENTAUTHCODE1234'), [
    'Secure-Join: vc-pubkey',
    `Secure-Join-Auth: DIFFERENTAUTHCODE1234`,
    `Autocrypt: ${autocryptHeader('contact@example.net', wrongKey.publicB64, true)}`,
  ]))
  assert.equal(h.sent.length, 1)
  assert.equal((await h.bridge.getStatus()).verified, false)
})

test('cancelling SecureJoin ignores late replies until it is restarted', async () => {
  const contact = await keyPair('contact@example.net')
  const h = await makeBridge(contact, { inviteUrl: inviteFor(contact) })
  const secret = secretFor(contact.fingerprint)

  await h.bridge.startSecureJoin()
  assert.equal(h.sent.length, 1)
  const cancelled = await h.bridge.cancelSecureJoin()
  assert.equal(cancelled.secureJoin.status, 'cancelled')
  assert.equal(cancelled.verified, false)
  assert.equal(h.sent.length, 1, 'cancelling does not send mail')

  await h.bridge.process(await buildSymmetricHandshake(h.cfg, contact, AUTH, secret, [
    'Secure-Join: vc-pubkey',
    `Secure-Join-Auth: ${AUTH}`,
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
  ]))
  assert.equal(h.sent.length, 1, 'a late vc-pubkey is ignored after cancel')

  const restarted = await h.bridge.startSecureJoin()
  assert.equal(restarted.secureJoin.status, 'request-sent')
  assert.equal(h.sent.length, 2)
})

test('Autocrypt mode keeps the legacy request and does not expose SecureJoin', async () => {
  const contact = await keyPair('contact@example.net')
  const h = await makeBridge(contact, { remoteMode: 'autocrypt' })
  await assert.rejects(() => h.bridge.startSecureJoin(), /only available in SecureJoin remote mode/)
  await h.bridge.startHandshake()
  assert.equal(h.sent.length, 1)
  assert.equal(parseRawHeaders(Buffer.from(h.sent[0].raw)).get('x-opencode-handshake'), 'autocrypt-request')
  assert.equal((await h.bridge.getStatus()).remoteMode, 'autocrypt')
})

test('binding a session announces a new thread with the switched subject', async () => {
  const contact = await keyPair('contact@example.net')
  const h = await makeBridge(contact)
  await h.bridge.bindSession('session-1')
  assert.equal(h.sent.length, 1)
  const headers = parseRawHeaders(Buffer.from(h.sent[0].raw))
  assert.match(headers.get('subject'), /Switched to SecureJoin/)
  assert.match(headers.get('subject'), /\[session:session-1\]/)
  assert.equal(headers.get('in-reply-to'), undefined)
  assert.equal(headers.get('references'), undefined)
  assert.equal(headers.get('x-opencode-notice'), 'session-binding')
  assert.equal((await h.bridge.getStatus()).sessionID, 'session-1')
})
