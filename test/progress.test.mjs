import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import * as openpgp from 'openpgp'
import { simpleParser } from 'mailparser'
import { BRIDGE_WATCH_EVENTS, createBridge } from '../src/bridge.js'
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
  return {
    privateKey: pair.privateKey,
    publicB64: armorToBase64(pair.publicKey.armor()),
    fingerprint: await keyFingerprint(armorToBase64(pair.publicKey.armor())),
  }
}

async function waitFor(promise, ms = 5000) {
  let timer
  try {
    await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms) }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

function harness(fingerprint, root, options = {}) {
  const cfg = loadConfig({
    address: 'bot@example.org',
    displayName: 'Bridge',
    imapHost: 'imap.example.org',
    imapPassword: 'test',
    smtpHost: 'smtp.example.org',
    smtpPassword: 'test',
    pinnedContact: 'contact@example.net',
    pinnedFingerprint: fingerprint,
    remoteMode: 'autocrypt',
    generateKey: false,
    attachmentDir: path.join(root, 'attachments'),
    ...options,
  }, {})
  cfg.remote.progressIntervalMs = 0

  const values = new Map()
  values.set('autocrypt.state', {
    sessions: {}, peers: {}, seen: [], threads: {}, sessionContacts: {},
    meta: { [`welcome:${cfg.pinned.contact}:${cfg.pinned.fingerprint}`]: Date.now() },
    handshake: { established: true, verified: true },
    watches: {}, pending: {}, questions: {}, sent: {},
  })
  const session = {
    id: 'session-1',
    title: 'Progress test',
    projectID: 'project-1',
    location: { directory: root },
    time: { updated: 10 },
  }
  let messages = []
  let release = () => {}
  let signalWait
  const waitCalled = new Promise((resolve) => { signalWait = resolve })
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
      async wait() {
        signalWait()
        return new Promise((resolve) => { release = resolve })
      },
      async context() { return messages },
    },
    event: {
      subscribe() {
        return (async function* () {})()
      },
    },
    location: { directory: root },
  }
  const sent = []
  const sender = {
    async send(raw, to, sendOptions = {}) {
      sent.push({ raw: raw.toString('utf8'), to, options: sendOptions })
    },
  }
  return {
    cfg, ctx, sent, sender, session, waitCalled,
    setMessages(value) { messages = value },
    release() { release() },
  }
}

function contactMail(contact) {
  return Buffer.from([
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    'Subject: Progress test',
    `Date: ${new Date().toUTCString()}`,
    'Message-ID: <progress-prompt@example.net>',
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    'build the mockup',
    '',
  ].join('\r\n'))
}

async function decrypted(sent, index, bot) {
  const armored = extractArmored(sent[index].raw)
  assert.ok(armored, 'mail is PGP/MIME encrypted')
  const result = await decryptMessage(armored, bot, bot.publicB64)
  assert.equal(result.signatureVerified, true)
  return result.data
}

async function decryptedText(sent, index, bot) {
  const parsed = await simpleParser(await decrypted(sent, index, bot))
  return String(parsed.text || '')
}

test('subscribes to the plugin-visible assistant text stream', () => {
  assert.ok(BRIDGE_WATCH_EVENTS.includes('session.text.delta'))
  assert.ok(!BRIDGE_WATCH_EVENTS.includes('message.part.delta'))
})

test('progressive mail is throttled, final mail sends only the remainder and attaches session files', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const root = await mkdtemp(path.join(os.tmpdir(), 'opencode-ac-progress-'))
  const artifact = path.join(root, 'mockup.html')
  await writeFile(artifact, '<html><body>mockup</body></html>')

  const h = harness(contact.fingerprint, root)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  const pending = bridge.process(contactMail(contact))
  await waitFor(h.waitCalled)

  h.setMessages([
    { id: 'user-message', type: 'user', content: [{ type: 'text', text: 'build the mockup' }] },
    {
      id: 'assistant-1',
      type: 'assistant',
      content: [
        { type: 'text', text: 'Working done' },
        {
          type: 'file',
          mime: 'text/html',
          filename: 'mockup.html',
          url: `file://${artifact}`,
          source: { type: 'file', path: artifact },
        },
      ],
    },
  ])

  await bridge.processEvent({
    type: 'session.text.delta',
    data: {
      sessionID: h.session.id,
      assistantMessageID: 'assistant-1',
      delta: 'Working ',
    },
  })

  h.release()
  await pending

  assert.equal(h.sent.length, 2, 'one progress mail and one final mail')
  const headers = h.sent.map((entry) => parseRawHeaders(entry.raw))
  assert.equal(headers[0].get('x-opencode-notice'), 'progress')
  assert.equal(headers[1].get('x-opencode-notice'), undefined)
  assert.equal(headers[0].get('subject'), headers[1].get('subject'), 'progress and final mail share a subject')
  assert.equal(headers[0].get('in-reply-to'), headers[1].get('in-reply-to'), 'progress and final mail share a thread')

  const progressText = await decryptedText(h.sent, 0, bot)
  const finalText = await decryptedText(h.sent, 1, bot)
  assert.match(progressText, /Working/)
  assert.doesNotMatch(progressText, /done/)
  assert.match(finalText, /done/)
  assert.doesNotMatch(finalText, /Working/)
  assert.match((await decrypted(h.sent, 1, bot)).toString('utf8'), /name="mockup\.html"/)
})

test('final mail includes deltas received after the throttled progress mail', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const root = await mkdtemp(path.join(os.tmpdir(), 'opencode-ac-progress-'))

  const h = harness(contact.fingerprint, root)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  const pending = bridge.process(contactMail(contact))
  await waitFor(h.waitCalled)
  h.setMessages([
    { id: 'user-message', type: 'user', content: [{ type: 'text', text: 'go' }] },
    { id: 'assistant-1', type: 'assistant', content: [{ type: 'text', text: 'Working done and more' }] },
  ])

  await bridge.processEvent({
    type: 'session.text.delta',
    data: { sessionID: h.session.id, assistantMessageID: 'assistant-1', delta: 'Working ' },
  })
  // The rest of the answer streams in inside the throttle window, so it does
  // not get its own progress mail but must still appear in the final mail.
  h.cfg.remote.progressIntervalMs = 60_000
  await bridge.processEvent({
    type: 'session.text.delta',
    data: { sessionID: h.session.id, assistantMessageID: 'assistant-1', delta: 'done and more' },
  })
  h.release()
  await pending

  assert.equal(h.sent.length, 2)
  const progressText = await decryptedText(h.sent, 0, bot)
  const finalText = await decryptedText(h.sent, 1, bot)
  assert.match(progressText, /Working/)
  assert.doesNotMatch(progressText, /done and more/)
  assert.match(finalText, /done and more/)
  assert.doesNotMatch(finalText, /Completed in session/)
  assert.doesNotMatch(finalText, /Working/)
})

test('a run that stops for a question still mails its leading streamed output', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const root = await mkdtemp(path.join(os.tmpdir(), 'opencode-ac-progress-'))

  const h = harness(contact.fingerprint, root)
  // Keep everything inside the throttle window: no separate progress mail.
  h.cfg.remote.progressIntervalMs = 60_000
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  const pending = bridge.process(contactMail(contact))
  await waitFor(h.waitCalled)
  // The question ends the run before an assistant message is committed.
  h.setMessages([
    { id: 'user-message', type: 'user', content: [{ type: 'text', text: 'go' }] },
  ])
  await bridge.processEvent({
    type: 'session.text.delta',
    data: {
      sessionID: h.session.id,
      assistantMessageID: 'assistant-1',
      delta: 'Leading output before the question ',
    },
  })
  h.release()
  await pending

  assert.equal(h.sent.length, 1)
  const finalText = await decryptedText(h.sent, 0, bot)
  assert.match(finalText, /Leading output before the question/)
})

test('streamed output is buffered when progressive mail is disabled', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const root = await mkdtemp(path.join(os.tmpdir(), 'opencode-ac-progress-'))

  const h = harness(contact.fingerprint, root)
  h.cfg.remote.progress = false
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  const pending = bridge.process(contactMail(contact))
  await waitFor(h.waitCalled)
  // The assistant message never commits because a question ends the run.
  h.setMessages([
    { id: 'user-message', type: 'user', content: [{ type: 'text', text: 'go' }] },
  ])
  await bridge.processEvent({
    type: 'session.text.delta',
    data: {
      sessionID: h.session.id,
      assistantMessageID: 'assistant-1',
      delta: 'Buffered even without progress mail ',
    },
  })
  h.release()
  await pending

  assert.equal(h.sent.length, 1, 'only the final mail is sent')
  const headers = parseRawHeaders(h.sent[0].raw)
  assert.equal(headers.get('x-opencode-notice'), undefined)
  assert.match(await decryptedText(h.sent, 0, bot), /Buffered even without progress mail/)
})

test('a committed full reply is mailed in one piece when progressive mail is disabled', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const root = await mkdtemp(path.join(os.tmpdir(), 'opencode-ac-progress-'))

  const h = harness(contact.fingerprint, root)
  h.cfg.remote.progress = false
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  const pending = bridge.process(contactMail(contact))
  await waitFor(h.waitCalled)
  h.setMessages([
    { id: 'user-message', type: 'user', content: [{ type: 'text', text: 'go' }] },
    { id: 'assistant-1', type: 'assistant', content: [{ type: 'text', text: 'Full committed answer' }] },
  ])
  h.release()
  await pending

  assert.equal(h.sent.length, 1, 'one final mail, no progress mail')
  assert.equal(parseRawHeaders(h.sent[0].raw).get('x-opencode-notice'), undefined)
  assert.match(await decryptedText(h.sent, 0, bot), /Full committed answer/)
})

test('a fully mailed progress answer still gets one short completion mail', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const root = await mkdtemp(path.join(os.tmpdir(), 'opencode-ac-progress-'))

  const h = harness(contact.fingerprint, root)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  const pending = bridge.process(contactMail(contact))
  await waitFor(h.waitCalled)
  h.setMessages([
    { id: 'user-message', type: 'user', content: [{ type: 'text', text: 'go' }] },
    { id: 'assistant-1', type: 'assistant', content: [{ type: 'text', text: 'All done' }] },
  ])
  await bridge.processEvent({
    type: 'session.text.delta',
    data: { sessionID: h.session.id, assistantMessageID: 'assistant-1', delta: 'All done' },
  })
  h.release()
  await pending

  assert.equal(h.sent.length, 2)
  const finalText = await decryptedText(h.sent, 1, bot)
  assert.match(finalText, /Completed in session session-1/)
  assert.doesNotMatch(finalText, /All done/)
})

test('session files outside the project are not attached', async () => {
  const bot = await keyPair('bot@example.org')
  const contact = await keyPair('contact@example.net')
  const root = await mkdtemp(path.join(os.tmpdir(), 'opencode-ac-progress-'))
  const outside = path.join(os.tmpdir(), `opencode-ac-outside-${Date.now()}.txt`)
  await writeFile(outside, 'secret')

  const h = harness(contact.fingerprint, root)
  const bridge = await createBridge(h.ctx, h.cfg, {
    identity: bot, sender: h.sender, log: () => {},
  })

  const pending = bridge.process(contactMail(contact))
  await waitFor(h.waitCalled)

  h.setMessages([
    { id: 'user-message', type: 'user', content: [{ type: 'text', text: 'build' }] },
    {
      id: 'assistant-1',
      type: 'assistant',
      content: [
        { type: 'text', text: 'done' },
        { type: 'file', mime: 'text/plain', filename: 'outside.txt', source: { type: 'file', path: outside } },
      ],
    },
  ])
  h.release()
  await pending

  assert.equal(h.sent.length, 1)
  const finalText = await decryptedText(h.sent, 0, bot)
  const finalMime = (await decrypted(h.sent, 0, bot)).toString('utf8')
  assert.match(finalText, /done/)
  assert.doesNotMatch(finalMime, /outside\.txt/)
})
