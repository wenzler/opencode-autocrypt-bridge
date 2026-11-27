import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { simpleParser } from 'mailparser'
import { createBridge } from '../src/bridge.js'
import { decryptMessage, keyFingerprint } from '../src/crypto.js'
import { loadConfig } from '../src/config.js'
import { armorToBase64, autocryptHeader } from '../src/headers.js'
import { extractArmored, parseRawHeaders } from '../src/mime.js'
import { orderedSessions } from '../src/session.js'

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
  const records = new Map()
  for (const session of options.sessions || []) records.set(session.id, session)
  const created = []
  const prompted = []
  const promptInputs = []
  const ctx = {
    storage: {
      async get(key) { return values.get(key) },
      async set(key, value) { values.set(key, value) },
    },
    session: {
      async create(input = {}) {
        const id = `session-${created.length + 1}`
        const record = {
          id,
          title: input.title || '',
          projectID: options.projectID || 'project-1',
          location: input.location || { directory: options.directory || '/tmp' },
          time: { updated: Date.now() },
        }
        records.set(id, record)
        created.push(record)
        return record
      },
      async get({ sessionID }) {
        const record = records.get(sessionID)
        if (!record) throw new Error(`Unknown session ${sessionID}`)
        return record
      },
      async list() { return { data: [...records.values()] } },
      async prompt(input) {
        prompted.push(input.sessionID)
        promptInputs.push(input)
        return { id: userId }
      },
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
  return { cfg, ctx, sent, sender, created, prompted, promptInputs, records }
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

function contactReply(contact, { subject = 'Re: first contact', text = 'hello', messageId = '<reply@example.net>', inReplyTo = '' } = {}) {
  const lines = [
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: ${messageId}`,
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
  ]
  if (inReplyTo) lines.push(`In-Reply-To: ${inReplyTo}`)
  lines.push(
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    text,
    '',
  )
  return Buffer.from(lines.join('\r\n'))
}

async function sentText(sent, bot, index = sent.length - 1) {
  const armored = extractArmored(sent[index].raw)
  assert.ok(armored, 'reply is PGP/MIME encrypted')
  const decrypted = await decryptMessage(armored, bot, bot.publicB64)
  assert.equal(decrypted.signatureVerified, true)
  const parsed = await simpleParser(decrypted.data)
  return String(parsed.text || '')
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
  const prompt = h.promptInputs[0]
  assert.equal(prompt.text.trim(), 'Hello from the pinned contact.')
  assert.equal(prompt.metadata.source, 'autocrypt-email')
  assert.equal(prompt.metadata.from, 'contact@example.net')
  assert.ok(prompt.metadata.sessionID)
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

test('outbound subjects carry the session marker used for reply routing', async () => {
  const bot = await keyPair('bot4@example.org')
  const contact = await keyPair('contact4@example.net')
  const h = harness(contact.fingerprint, { assistantText: 'first answer' })
  const bridge = await createBridge(h.ctx, h.cfg, { identity: bot, sender: h.sender, log: () => {} })

  await bridge.process(firstContactMail(contact))

  assert.equal(h.sent.length, 2)
  assert.match(parseRawHeaders(h.sent[0].raw).get('subject'), /\[session:session-1\]/)
  assert.match(parseRawHeaders(h.sent[1].raw).get('subject'), /\[session:session-1\]/)
  assert.deepEqual(h.prompted, ['session-1'])
  assert.equal(h.created.length, 1)
})

test('a Delta Chat subject marker routes a reply to another existing session', async () => {
  const bot = await keyPair('bot5@example.org')
  const contact = await keyPair('contact5@example.net')
  const existing = {
    id: 'ses_main',
    title: 'Main project',
    projectID: 'p1',
    location: { directory: '/work/alpha' },
    time: { updated: 10 },
  }
  const h = harness(contact.fingerprint, { assistantText: 'routed answer', sessions: [existing] })
  const bridge = await createBridge(h.ctx, h.cfg, { identity: bot, sender: h.sender, log: () => {} })

  await bridge.process(firstContactMail(contact))
  await bridge.process(contactReply(contact, {
    subject: 'Re: first contact [session:ses_main]',
    text: 'route me',
    messageId: '<routed@example.net>',
  }))

  assert.deepEqual(h.prompted, ['session-1', 'ses_main'])
  assert.equal(h.created.length, 1)
  assert.match(parseRawHeaders(h.sent.at(-1).raw).get('subject'), /\[session:ses_main\]/)
})

test('thread headers route replies when a mail client drops the subject marker', async () => {
  const bot = await keyPair('bot6@example.org')
  const contact = await keyPair('contact6@example.net')
  const h = harness(contact.fingerprint, { assistantText: 'threaded answer' })
  const bridge = await createBridge(h.ctx, h.cfg, { identity: bot, sender: h.sender, log: () => {} })

  await bridge.process(firstContactMail(contact))
  const outboundID = parseRawHeaders(h.sent[0].raw).get('message-id')
  await bridge.process(contactReply(contact, {
    subject: 'Re: first contact',
    text: 'threaded',
    messageId: '<threaded@example.net>',
    inReplyTo: outboundID,
  }))

  assert.deepEqual(h.prompted, ['session-1', 'session-1'])
  assert.equal(h.created.length, 1)
})

test('!use switches the email thread and prompts the remaining text there', async () => {
  const bot = await keyPair('bot7@example.org')
  const contact = await keyPair('contact7@example.net')
  const existing = {
    id: 'ses_main',
    title: 'Main project',
    projectID: 'p1',
    location: { directory: '/work/alpha' },
    time: { updated: 10 },
  }
  const h = harness(contact.fingerprint, { assistantText: 'switched answer', sessions: [existing] })
  const bridge = await createBridge(h.ctx, h.cfg, { identity: bot, sender: h.sender, log: () => {} })

  await bridge.process(firstContactMail(contact))
  await bridge.process(contactReply(contact, {
    subject: 'Re: first contact [session:session-1]',
    text: '!use ses_main please inspect',
    messageId: '<switch@example.net>',
  }))

  assert.deepEqual(h.prompted, ['session-1', 'ses_main'])
  assert.match(h.promptInputs[1].text, /Using session ses_main/)
  assert.match(h.promptInputs[1].text, /please inspect/)
  assert.match(parseRawHeaders(h.sent.at(-1).raw).get('subject'), /\[session:ses_main\]/)
})

test('!session #n switches using the number printed by !sessions', async () => {
  const bot = await keyPair('bot7a@example.org')
  const contact = await keyPair('contact7a@example.net')
  const existing = {
    id: 'ses_main',
    title: 'Main project',
    projectID: 'p1',
    location: { directory: '/work/alpha' },
    time: { updated: 10 },
  }
  const h = harness(contact.fingerprint, { assistantText: 'numbered answer', sessions: [existing] })
  const bridge = await createBridge(h.ctx, h.cfg, { identity: bot, sender: h.sender, log: () => {} })

  await bridge.process(firstContactMail(contact))
  const displayed = orderedSessions(await bridge.listSessions())
  const number = displayed.findIndex((session) => session.id === 'ses_main') + 1
  assert.ok(number > 0)
  await bridge.process(contactReply(contact, {
    subject: 'Re: first contact [session:session-1]',
    text: `!session #${number} please inspect`,
    messageId: '<numbered-switch@example.net>',
  }))

  assert.deepEqual(h.prompted, ['session-1', 'ses_main'])
  assert.match(h.promptInputs[1].text, /please inspect/)
  assert.match(parseRawHeaders(h.sent.at(-1).raw).get('subject'), /\[session:ses_main\]/)
})

test('!sessions lists projects and sessions without prompting the agent', async () => {
  const bot = await keyPair('bot8@example.org')
  const contact = await keyPair('contact8@example.net')
  const existing = {
    id: 'ses_main',
    title: 'Main project',
    projectID: 'p1',
    location: { directory: '/work/alpha' },
    time: { updated: 10 },
  }
  const h = harness(contact.fingerprint, { sessions: [existing] })
  const bridge = await createBridge(h.ctx, h.cfg, { identity: bot, sender: h.sender, log: () => {} })

  await bridge.process(firstContactMail(contact))
  const before = h.sent.length
  await bridge.process(contactReply(contact, {
    subject: 'Re: first contact [session:session-1]',
    text: '!sessions',
    messageId: '<list@example.net>',
  }))

  assert.equal(h.prompted.length, 1)
  assert.equal(h.sent.length, before + 1)
  const text = await sentText(h.sent, bot)
  assert.match(text, /OpenCode sessions/)
  assert.match(text, /ses_main/)
  assert.match(text, /!use <#n\|session-id>/)
})
