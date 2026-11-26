import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { armorToBase64 } from '../src/headers.js'
import { encryptMime, decryptMessage, keyFingerprint, validatePublicKey } from '../src/crypto.js'

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

async function encryptFromContact(text, contact, bot) {
  const message = await openpgp.createMessage({ binary: Uint8Array.from(Buffer.from(text)) })
  const keys = await Promise.all([bot.publicB64, contact.publicB64].map(async (b64) =>
    openpgp.readKey({ binaryKey: Uint8Array.from(Buffer.from(b64, 'base64')) })))
  return openpgp.encrypt({
    message,
    encryptionKeys: keys,
    signingKeys: contact.privateKey,
    format: 'armored',
  })
}

test('pinned-key encrypt/decrypt verifies the sender signature', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')

  await validatePublicKey(contact.publicB64)
  const armored = await encryptFromContact('hello', contact, bot)
  const decrypted = await decryptMessage(armored, { privateKey: bot.privateKey }, contact.publicB64)

  assert.equal(decrypted.data.toString('utf8').trim(), 'hello')
  assert.equal(decrypted.signatureVerified, true)
})

test('pinned-key verification rejects a signature from a different key', async () => {
  const bot = await keyPair('bot2@example.org')
  const contact = await keyPair('contact2@example.net')
  const stranger = await keyPair('stranger@example.net')

  const armored = await encryptFromContact('secret', contact, bot)
  await assert.rejects(
    decryptMessage(armored, { privateKey: bot.privateKey }, stranger.publicB64),
  )
})

test('outbound encryptMime includes the bot signature for the contact', async () => {
  const bot = await keyPair('bot3@example.org')
  const contact = await keyPair('contact3@example.net')
  const identity = { privateKey: bot.privateKey, publicB64: bot.publicB64 }
  const armored = await encryptMime(Buffer.from('reply'), identity, [contact.publicB64])
  const decrypted = await decryptMessage(armored, { privateKey: contact.privateKey }, bot.publicB64)
  assert.equal(decrypted.data.toString('utf8').trim(), 'reply')
  assert.equal(decrypted.signatureVerified, true)
})

test('pinned fingerprint matches a key and rejects a different identity', async () => {
  const contact = await keyPair('pinned@example.net')
  const fingerprint = await keyFingerprint(contact.publicB64)
  assert.match(fingerprint, /^[0-9A-F]{40}$/)

  assert.equal(await validatePublicKey(contact.publicB64, fingerprint.toLowerCase()), fingerprint)
  await assert.rejects(
    validatePublicKey(contact.publicB64, '0'.repeat(40)),
    /fingerprint/i,
  )
})

test('validatePublicKey rejects a private key', async () => {
  const pair = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: 'bad', email: 'bad@example.net' }],
    format: 'object',
  })
  const privateB64 = Buffer.from(await pair.privateKey.write()).toString('base64')
  await assert.rejects(validatePublicKey(privateB64), /public key/i)
})
