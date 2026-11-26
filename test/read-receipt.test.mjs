import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { createBridge } from '../src/bridge.js'
import { decryptMessage, encryptMime, keyFingerprint } from '../src/crypto.js'
import { loadConfig } from '../src/config.js'
import { armorToBase64, autocryptHeader } from '../src/headers.js'
import {
  buildPgpMime,
  buildReadReceiptMime,
  extractArmored,
  parseDispositionNotification,
  parseRawHeaders,
} from '../src/mime.js'

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
    attachmentDir: '/tmp/opencode-autocrypt-bridge-receipts',
    ...options,
  }, {})
  const values = new Map()
  const session = {
    id: 'session-1',
    title: 'Receipt test',
    projectID: 'project-1',
    location: { directory: '/work/alpha' },
    time: { updated: 10 },
  }
  const questionAnswers = []
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
      async prompt() { return { id: 'user-message' } },
      async wait() {},
      async context() { return [] },
    },
    event: {
      subscribe() {
        return (async function* () {})()
      },
    },
    location: { directory: '/tmp' },
  }
  const sent = []
  const sender = {
    async send(raw, to) { sent.push({ raw: raw.toString('utf8'), to }) },
  }
  return { cfg, ctx, values, sent, sender, session, questionAnswers }
}

function contactMail(contact, { text = 'hello', messageId = '<contact-1@example.net>', headers = [] } = {}) {
  return Buffer.from([
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    'Subject: Receipt test',
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: ${messageId}`,
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    ...headers,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    text,
    '',
  ].join('\r\n'))
}

function mdnMail(contact, originalMessageID) {
  return contactMail(contact, {
    text: 'This message is only a receipt.',
    messageId: '<mdn-1@example.net>',
    headers: [
      'Subject: Receipt Notification',
      'Chat-Version: 1.0',
      'Auto-Submitted: auto-replied',
      'Content-Type: multipart/report; report-type=disposition-notification; boundary="mdn-test"',
      '',
      '--mdn-test',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'This is a receipt notification.',
      '--mdn-test',
      'Content-Type: message/disposition-notification',
      '',
      `Original-Message-ID: ${originalMessageID}`,
      'Disposition: manual-action/MDN-sent-automatically; displayed',
      '--mdn-test--',
      '',
    ],
  })
}

async function encryptedMdnMail(contact, bot, originalMessageID) {
  const receipt = buildReadReceiptMime({ originalMessageID })
  const armored = await encryptMime(receipt.entity, contact, [bot.publicB64])
  const pgp = buildPgpMime(armored)
  return Buffer.from([
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    'Subject: Receipt Notification',
    `Date: ${new Date().toUTCString()}`,
    'Message-ID: <encrypted-mdn@example.net>',
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    'Chat-Version: 1.0',
    'Auto-Submitted: auto-replied',
    `Content-Type: ${pgp.contentType}`,
    '',
    pgp.body.toString('utf8'),
  ].join('\r\n'))
}

async function decryptedSent(sent, index, bot) {
  const armored = extractArmored(sent[index].raw)
  assert.ok(armored, 'sent mail is PGP/MIME encrypted')
  const decrypted = await decryptMessage(armored, bot, bot.publicB64)
  assert.equal(decrypted.signatureVerified, true)
  return decrypted.data
}

test('outbound mail requests an encrypted read receipt from the pinned contact', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const h = harness(contact.fingerprint)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  await bridge.process(contactMail(contact))

  assert.equal(parseRawHeaders(h.sent[0].raw).get('chat-disposition-notification-to'), 'bot@example.org')
  assert.equal(parseRawHeaders(h.sent.at(-1).raw).get('chat-disposition-notification-to'), 'bot@example.org')
})

test('an inbound receipt request produces an encrypted Delta Chat MDN', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const h = harness(contact.fingerprint)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  await bridge.process(contactMail(contact, {
    text: '!status',
    messageId: '<contact-receipt@example.net>',
    headers: ['Chat-Disposition-Notification-To: bot@example.org'],
  }))

  const headers = h.sent.map((entry) => parseRawHeaders(entry.raw))
  const receiptIndex = headers.findIndex((entry) => entry.get('subject') === 'Receipt Notification')
  assert.notEqual(receiptIndex, -1)
  assert.equal(headers.filter((entry) => entry.get('subject') === 'Receipt Notification').length, 1)
  const receipt = headers[receiptIndex]
  assert.equal(receipt.get('auto-submitted'), 'auto-replied')
  assert.equal(receipt.get('in-reply-to'), undefined)
  assert.equal(receipt.get('chat-disposition-notification-to'), undefined)
  const parsed = parseDispositionNotification(await decryptedSent(h.sent, receiptIndex, bot))
  assert.deepEqual(parsed, {
    disposition: 'manual-action/MDN-sent-automatically; displayed',
    originalMessageID: '<contact-receipt@example.net>',
  })
  const statusReply = headers.find((entry) => entry.get('x-opencode-command') === 'session-command')
  assert.ok(statusReply, 'status command was still answered')
  assert.match(statusReply.get('subject'), /Receipt test/)
})

test('an inbound MDN confirms the outbound message without generating mail', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const h = harness(contact.fingerprint)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  await bridge.process(contactMail(contact))
  const outboundID = parseRawHeaders(h.sent[0].raw).get('message-id')
  const before = h.sent.length
  await bridge.process(mdnMail(contact, outboundID))

  assert.equal(h.sent.length, before)
  const state = h.values.get('autocrypt.state')
  assert.ok(state.sent[outboundID.replace(/^<|>$/g, '')].receiptAt)
  const status = await bridge.getStatus()
  assert.ok(status.lastReceiptAt > 0)
})

test('an encrypted Delta Chat MDN is recognized without generating another mail', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const h = harness(contact.fingerprint)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  await bridge.process(contactMail(contact))
  const outboundID = parseRawHeaders(h.sent[0].raw).get('message-id')
  const before = h.sent.length
  await bridge.process(await encryptedMdnMail(contact, bot, outboundID))

  assert.equal(h.sent.length, before)
  const state = h.values.get('autocrypt.state')
  assert.ok(state.sent[outboundID.replace(/^<|>$/g, '')].receiptAt)
})

test('a receipt request addressed to another mailbox is ignored', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const h = harness(contact.fingerprint)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  await bridge.process(contactMail(contact, {
    headers: ['Chat-Disposition-Notification-To: other@example.org'],
  }))

  assert.equal(h.sent.filter((entry) => parseRawHeaders(entry.raw).get('subject') === 'Receipt Notification').length, 0)
})

test('one question answer produces one terminal notice, not a success/error pair', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const h = harness(contact.fingerprint)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot,
    sender: h.sender,
    log: () => {},
    onQuestionAnswer: (input) => h.questionAnswers.push(input),
  })

  await bridge.process(contactMail(contact))
  const form = {
    id: 'frm-duplicate-check',
    sessionID: h.session.id,
    title: 'Questions',
    metadata: { kind: 'question' },
    fields: [{ key: 'q0', type: 'string', options: [{ value: 'diff', label: 'Diff' }] }],
  }
  await Promise.all([
    bridge.processEvent({ type: 'form.created', data: { form } }),
    bridge.processEvent({ type: 'form.created', data: { form } }),
  ])
  const code = parseRawHeaders(h.sent.at(-1).raw).get('x-opencode-question')
  assert.equal(h.sent.filter((entry) => parseRawHeaders(entry.raw).get('x-opencode-question') === code).length, 1)

  const answer = (messageId) => contactMail(contact, {
    text: `!answer ${code} 1`,
    messageId,
    headers: ['Chat-Disposition-Notification-To: bot@example.org'],
  })
  await bridge.process(answer('<answer-first@example.net>'))
  await bridge.process(answer('<answer-second@example.net>'))
  assert.equal(h.questionAnswers.length, 1)

  await bridge.confirmQuestionReply({ formID: form.id, ok: true })
  await bridge.confirmQuestionReply({ formID: form.id, ok: true })
  await bridge.confirmQuestionReply({ formID: form.id, ok: false, error: '409 duplicate reply' })

  const headers = h.sent.map((entry) => parseRawHeaders(entry.raw))
  const completions = headers.filter((entry) => entry.get('x-opencode-command') === 'question-answered')
  const errors = headers.filter((entry) => entry.get('x-opencode-command') === 'error')
  assert.equal(completions.length, 1)
  assert.equal(errors.length, 0)
  assert.doesNotMatch(h.sent.at(-1).raw, /could not complete/i)
})

test('a failed desktop reply can be retried and still produces one notice per attempt', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const h = harness(contact.fingerprint)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot,
    sender: h.sender,
    log: () => {},
    onQuestionAnswer: (input) => h.questionAnswers.push(input),
  })

  await bridge.process(contactMail(contact))
  const form = {
    id: 'frm-retry-check',
    sessionID: h.session.id,
    title: 'Questions',
    metadata: { kind: 'question' },
    fields: [{ key: 'q0', type: 'string', options: [{ value: 'diff', label: 'Diff' }] }],
  }
  await bridge.processEvent({ type: 'form.created', data: { form } })
  const code = parseRawHeaders(h.sent.at(-1).raw).get('x-opencode-question')
  const answer = (messageId) => contactMail(contact, {
    text: `!answer ${code} 1`,
    messageId,
  })

  await bridge.process(answer('<retry-first@example.net>'))
  await bridge.confirmQuestionReply({ formID: form.id, ok: false, error: 'desktop was busy' })
  await bridge.confirmQuestionReply({ formID: form.id, ok: false, error: 'duplicate 409' })
  await bridge.process(answer('<retry-second@example.net>'))
  await bridge.confirmQuestionReply({ formID: form.id, ok: true })
  await bridge.confirmQuestionReply({ formID: form.id, ok: false, error: 'late 409' })

  assert.equal(h.questionAnswers.length, 2)
  const headers = h.sent.map((entry) => parseRawHeaders(entry.raw))
  assert.equal(headers.filter((entry) => entry.get('x-opencode-command') === 'error').length, 1)
  assert.equal(headers.filter((entry) => entry.get('x-opencode-command') === 'question-answered').length, 1)
  assert.equal(parseRawHeaders(h.sent.at(-1).raw).get('x-opencode-command'), 'question-answered')
})
