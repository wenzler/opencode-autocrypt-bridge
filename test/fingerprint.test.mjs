import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { armorToBase64, autocryptHeader } from '../src/headers.js'
import { keyFingerprint } from '../src/crypto.js'
import { parseIncoming } from '../src/mail.js'

async function keyPair(email) {
  const pair = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: email.split('@')[0], email }],
    format: 'object',
  })
  return { publicB64: armorToBase64(pair.publicKey.armor()) }
}

test('parseIncoming accepts a matching Autocrypt fingerprint and rejects a different one', async () => {
  const contact = await keyPair('contact@example.net')
  const fingerprint = await keyFingerprint(contact.publicB64)
  const cfg = {
    attachmentDir: '/tmp/opencode-autocrypt-bridge-test',
    pinned: { contact: 'contact@example.net', fingerprint, requireEncrypted: false },
  }
  const raw = Buffer.from([
    'From: contact@example.net',
    'Message-ID: <pinned@example.net>',
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    '',
    'hello from pinned contact',
    '',
  ].join('\r\n'))

  const message = await parseIncoming(raw, cfg, {}, () => {}, cfg.pinned, '')
  assert.equal(message.from, 'contact@example.net')
  assert.equal(message.autocrypt.keydata, contact.publicB64)
  assert.equal(message.text.trim(), 'hello from pinned contact')

  const wrong = { ...cfg, pinned: { ...cfg.pinned, fingerprint: '0'.repeat(40) } }
  await assert.rejects(
    parseIncoming(raw, wrong, {}, () => {}, wrong.pinned, ''),
    /fingerprint/i,
  )
})

test('parseIncoming rejects an Autocrypt header from a different address', async () => {
  const contact = await keyPair('contact@example.net')
  const fingerprint = await keyFingerprint(contact.publicB64)
  const cfg = {
    attachmentDir: '/tmp/opencode-autocrypt-bridge-test',
    pinned: { contact: 'contact@example.net', fingerprint, requireEncrypted: false },
  }
  const raw = Buffer.from([
    'From: stranger@example.net',
    'Message-ID: <unpinned@example.net>',
    autocryptHeader('stranger@example.net', contact.publicB64, true),
    '',
    'hello',
    '',
  ].join('\r\n'))
  await assert.rejects(
    parseIncoming(raw, cfg, {}, () => {}, cfg.pinned, ''),
    /pinned contact/i,
  )
})
