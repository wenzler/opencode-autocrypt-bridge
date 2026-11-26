import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { simpleParser } from 'mailparser'
import { createBridge } from '../src/bridge.js'
import { decryptMessage, keyFingerprint } from '../src/crypto.js'
import { loadConfig } from '../src/config.js'
import { armorToBase64, autocryptHeader } from '../src/headers.js'
import { extractArmored, parseRawHeaders } from '../src/mime.js'

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

function harness(fingerprint, options = {}) {
  const cfg = loadConfig({
    address: 'bot@example.org',
    displayName: 'Bridge',
    imapHost: 'imap.example.org',
    imapPassword: 'test',
    smtpHost: 'smtp.example.org',
    smtpPassword: 'test',
    pinnedContact: 'contact@example.net',
    pinnedFingerprint: fingerprint,
    generateKey: false,
    attachmentDir: '/tmp/opencode-autocrypt-bridge-test',
  }, {})
  const values = new Map()
  const userId = 'user-message'
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {
      async create() { return { id: 'session-1' } },
      async prompt() { return { id: userId } },
      async wait() {},
      async context() {
        if (!options.assistantText) return []
        return [
          { id: userId, type: 'user', content: [] },
          { id: 'assistant-1', type: 'assistant', content: [{ type: 'text', text: options.assistantText }] },
        ]
      },
    },
    location: { directory: '/tmp' },
  }
  const sent = []
  const sender = {
    async send(raw, to) { sent.push({ raw: raw.toString('utf8'), to }) },
  }
  return { cfg, ctx, sent, sender }
}

function firstContactMail(contact) {
  return Buffer.from([
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    'Subject: first contact',
    `Date: ${new Date().toUTCString()}`,
    'Message-ID: <first-contact@example.net>',
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    'Hello from the pinned contact.',
    '',
  ].join('\r\n'))
}

test('a matching Autocrypt fingerprint learns the key and sends an encrypted confirmation', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const h = harness(contact.fingerprint)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot,
    sender: h.sender,
    log: () => {},
  })

  await bridge.process(firstContactMail(contact))

  const status = await bridge.getStatus()
  assert.equal(status.established, true)
  assert.equal(status.verified, true)
  assert.equal(status.learnedFingerprint, contact.fingerprint)
  assert.equal(h.sent.length, 1)
  assert.equal(h.sent[0].to, 'contact@example.net')
  const outer = parseRawHeaders(h.sent[0].raw)
  assert.match(outer.get('autocrypt'), /addr=bot@example\.org/)
  assert.equal(outer.get('chat-version'), '1.0')

  const armored = extractArmored(h.sent[0].raw)
  assert.ok(armored, 'confirmation is PGP/MIME encrypted')
  const decrypted = await decryptMessage(armored, bot, bot.publicB64)
  assert.equal(decrypted.signatureVerified, true)
  const parsed = await simpleParser(decrypted.data)
  const text = String(parsed.text || '')
  assert.match(text, /Key confirmed for contact@example\.net/)
  assert.match(text, new RegExp(contact.fingerprint))
})

test('established replies keep the Autocrypt header and Chat-Version marker', async () => {
  const bot = await keyPair('bot3@example.org')
  const contact = await keyPair('contact3@example.net')
  const h = harness(contact.fingerprint, { assistantText: 'Encrypted answer' })
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot,
    sender: h.sender,
    log: () => {},
  })

  await bridge.process(firstContactMail(contact))

  const status = await bridge.getStatus()
  assert.equal(status.established, true)
  assert.equal(status.verified, true)
  assert.equal(h.sent.length, 2)
  const reply = parseRawHeaders(h.sent[1].raw)
  assert.match(reply.get('autocrypt'), /addr=bot@example\.org/)
  assert.equal(reply.get('chat-version'), '1.0')
  assert.equal(reply.get('secure-join'), undefined)
  assert.match(h.sent[1].raw, /multipart\/encrypted/)
})

test('a mismatched Autocrypt fingerprint is rejected without sending anything', async () => {
  const bot = await keyPair('bot2@example.org')
  const contact = await keyPair('contact2@example.net')
  const h = harness('1'.repeat(40))
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot,
    sender: h.sender,
    log: () => {},
  })

  await bridge.process(firstContactMail(contact))

  const status = await bridge.getStatus()
  assert.equal(status.established, false)
  assert.equal(status.learnedFingerprint, '')
  assert.equal(h.sent.length, 0)
})
