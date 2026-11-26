import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { loadConfig } from '../src/config.js'
import { readPeerKey } from '../src/crypto.js'
import { armorToBase64, unfold } from '../src/headers.js'
import { buildInnerMime, buildMail, parseRawHeaders } from '../src/mime.js'

async function keyPair(email) {
  const pair = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: email.split('@')[0], email }],
    format: 'object',
  })
  return {
    publicB64: armorToBase64(pair.publicKey.armor()),
    publicArmored: pair.publicKey.armor(),
    fingerprint: pair.publicKey.getFingerprint().toUpperCase(),
  }
}

function config(contact, overrides = {}) {
  return loadConfig({
    address: 'bot@example.org',
    displayName: 'Bridge',
    imapHost: 'imap.example.org',
    imapPassword: 'test',
    smtpHost: 'smtp.example.org',
    smtpPassword: 'test',
    pinnedContact: 'contact@example.net',
    pinnedFingerprint: contact.fingerprint,
    pinnedContactKey: contact.publicArmored,
    ...overrides,
  }, {})
}

function outbound(cfg, publicB64) {
  const inner = buildInnerMime({ text: 'hello' })
  return parseRawHeaders(buildMail({
    cfg,
    to: 'contact@example.net',
    subject: 'Autocrypt standard check',
    messageId: '<autocrypt-standard@example.org>',
    publicB64,
    contentType: inner.contentType,
    body: inner.body,
  }))
}

test('outbound mail has a valid Autocrypt header with the sender public key', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const cfg = config(contact)
  const headers = outbound(cfg, bot.publicB64)

  const value = unfold(headers.get('autocrypt') || '')
  // parseRawHeaders unfolds continuation lines into spaces; Autocrypt parsing
  // strips that whitespace before base64-decoding keydata.
  const compact = value.replace(/\s+/g, '')
  assert.match(compact, /^addr=bot@example\.org;prefer-encrypt=mutual;keydata=/)
  const keydata = compact.slice(compact.indexOf('keydata=') + 'keydata='.length)
  assert.ok(keydata && /^[A-Za-z0-9+/=]+$/.test(keydata), 'keydata is unwrapped base64')
  assert.equal(compact.slice(-keydata.length), keydata, 'keydata is the last attribute')

  const binary = Buffer.from(keydata, 'base64')
  assert.ok(binary.length > 0, 'keydata decodes to OpenPGP packets')
  const key = await readPeerKey(keydata)
  assert.equal(key.isPrivate(), false, 'keydata must not contain secret material')
  assert.equal(key.getFingerprint().toUpperCase(), bot.fingerprint)
  assert.equal(headers.get('chat-version'), '1.0')
})

test('nopreference keys omit prefer-encrypt as Autocrypt Level 1 permits', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const cfg = config(contact, { preferEncryptMutual: false })
  const value = unfold(outbound(cfg, bot.publicB64).get('autocrypt') || '')

  assert.match(value, /^addr=bot@example\.org; keydata=/)
  assert.doesNotMatch(value, /prefer-encrypt=/)
})
