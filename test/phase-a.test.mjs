import test from 'node:test'
import assert from 'node:assert/strict'
import * as openpgp from 'openpgp'
import { simpleParser } from 'mailparser'
import {
  classifyPermission,
  decisionCode,
  formatDecisionRequest,
  formatRemoteHelp,
  parseQuestionAnswers,
} from '../src/commands.js'
import { createBridge } from '../src/bridge.js'
import { loadConfig } from '../src/config.js'
import { decryptMessage, keyFingerprint } from '../src/crypto.js'
import { armorToBase64, autocryptHeader } from '../src/headers.js'
import { extractArmored } from '../src/mime.js'
import { parseSessionCommand } from '../src/session.js'

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

async function sentTexts(sent, identity) {
  const texts = []
  for (const entry of sent) {
    const armored = extractArmored(entry.raw)
    const bytes = armored
      ? (await decryptMessage(armored, identity, identity.publicB64)).data
      : Buffer.from(entry.raw)
    const parsed = await simpleParser(bytes)
    texts.push(String(parsed.text || ''))
  }
  return texts
}

function harness(fingerprint, overrides = {}, options = {}) {
  const cfg = loadConfig({
    address: 'bot@example.org',
    displayName: 'Bridge',
    imapHost: 'imap.example.org',
    imapPassword: 'test',
    smtpHost: 'smtp.example.org',
    smtpPassword: 'test',
    pinnedContact: 'contact@example.net',
    pinnedFingerprint: fingerprint,
    attachmentDir: '/tmp/opencode-autocrypt-bridge-phase-a',
    ...overrides,
  }, {})
  const values = new Map()
  const session = {
    id: 'session-1',
    title: 'Phase A',
    projectID: 'project-1',
    location: { directory: '/work/alpha' },
    time: { updated: 10 },
  }
  const permissionReplies = []
  const questionAnswers = []
  const terminalReads = []
  const prompts = []
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
      async prompt(input) { prompts.push(input); return { id: 'user-message' } },
      async wait() {},
      async context() {
        if (!options.assistantText) return []
        return [
          { id: 'user-message', type: 'user', content: [] },
          { id: 'assistant-1', type: 'assistant', content: [{ type: 'text', text: options.assistantText }] },
        ]
      },
    },
    permission: {
      async reply(input) { permissionReplies.push(input) },
    },
    experimental: {
      terminal: {
        async read(input) {
          terminalReads.push(input)
          return 'terminal line 1\nterminal line 2'
        },
      },
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
  return { cfg, ctx, sent, sender, session, permissionReplies, questionAnswers, prompts, terminalReads }
}

function contactMail(contact, { subject = 'Phase A', text = 'hello', messageId = '<phase-a-1@example.net>' } = {}) {
  return Buffer.from([
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: ${messageId}`,
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    text,
    '',
  ].join('\r\n'))
}

function contactReply(contact, { subject = 'Re: Phase A [session:session-1]', text = 'hello', messageId = '<phase-a-reply@example.net>' } = {}) {
  return Buffer.from([
    'From: Contact <contact@example.net>',
    'To: <bot@example.org>',
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: ${messageId}`,
    `Autocrypt: ${autocryptHeader('contact@example.net', contact.publicB64, true)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    text,
    '',
  ].join('\r\n'))
}

test('remote command parser keeps codes, choices and counts', () => {
  assert.deepEqual(parseSessionCommand('!approve D-ABC123 always'), {
    command: 'approve', argument: 'D-ABC123', rest: 'always',
  })
  assert.deepEqual(parseSessionCommand('!answer D-ABC123 1;2,3'), {
    command: 'answer', argument: 'D-ABC123', rest: '1;2,3',
  })
  assert.deepEqual(parseSessionCommand('!tail 40'), {
    command: 'tail', argument: '40', rest: '',
  })
  assert.deepEqual(parseSessionCommand('!reject D-ABC123 too risky'), {
    command: 'deny', argument: 'D-ABC123', rest: 'too risky',
  })
})

test('permission classification treats shell-like and out-of-project access as high risk', () => {
  assert.deepEqual(classifyPermission('read', ['/work/alpha/README.md'], '/work/alpha'), {
    level: 'low', reasons: [],
  })
  assert.equal(classifyPermission('write', ['/work/alpha/package.json'], '/work/alpha').level, 'medium')
  assert.equal(classifyPermission('bash', ['*'], '/work/alpha').level, 'high')
  const outside = classifyPermission('read', ['/etc/passwd'], '/work/alpha')
  assert.equal(outside.level, 'high')
  assert.match(outside.reasons.join(' '), /outside project directory/)
})

test('numbered choices map to OpenCode form answers', () => {
  const fields = [
    {
      key: 'q0',
      type: 'string',
      options: [{ value: 'diff', label: 'Diff' }, { value: 'code', label: 'Code' }],
    },
    {
      key: 'q1',
      type: 'multiselect',
      options: [{ value: 'a', label: 'A' }, { value: 'b', label: 'B' }],
    },
  ]
  assert.deepEqual(parseQuestionAnswers(fields, '1;1,2'), {
    answer: { q0: 'diff', q1: ['a', 'b'] },
  })
  assert.match(parseQuestionAnswers(fields, '7').error, /not listed/)
})

test('question answers use the field type expected by session.form.reply', () => {
  const fields = [
    { key: 'q0', type: 'number' },
    { key: 'q1', type: 'integer' },
    { key: 'q2', type: 'boolean' },
    { key: 'q3', type: 'string' },
  ]
  assert.deepEqual(parseQuestionAnswers(fields, '1.5;2;yes;custom'), {
    answer: { q0: 1.5, q1: 2, q2: true, q3: 'custom' },
  })
  assert.match(parseQuestionAnswers([fields[1]], '1.5').error, /whole number/)
  assert.match(parseQuestionAnswers([fields[2]], 'maybe').error, /true.*false/)
})

test('dynamic help shows the live gate state', () => {
  const text = formatRemoteHelp({
    decisions: true, highRiskDecisions: false, questions: true,
    peek: false, tail: true, sendFiles: true, watch: true,
  }, { sessionID: 'session-1' })
  assert.match(text, /!answer <code>/)
  assert.match(text, /!approve <code>/)
  assert.match(text, /Permission decisions by email: on/)
  assert.match(text, /Multiple-choice answers by email: on/)
  assert.match(text, /High-risk decisions by email: off/)
  assert.match(text, /!peek \[session-id\] \[count\].*off:/)
  assert.match(text, /!commands, !shortcuts/)
})

test('decision mails distinguish a disabled gate from a high-risk request', () => {
  const risk = { level: 'low', reasons: [] }
  const disabled = formatDecisionRequest({
    code: 'D-ABC123', action: 'read', risk, enabled: false, canAnswer: false, sessionID: 'session-1',
  })
  assert.match(disabled, /Permission decisions by email are disabled/)
  assert.doesNotMatch(disabled, /HIGH RISK/)

  const highRisk = formatDecisionRequest({
    code: 'D-ABC123',
    action: 'bash',
    risk: { level: 'high', reasons: ['action bash'] },
    enabled: true,
    canAnswer: false,
    sessionID: 'session-1',
  })
  assert.match(highRisk, /HIGH RISK/)
  assert.match(highRisk, /High-risk decisions by email/)
})

test('low-risk permission decisions are answered through ctx.permission.reply', async () => {
  const contact = await keyPair('contact@example.net')
  const h = harness(await keyFingerprint(contact.publicB64))
  const bridge = await createBridge(h.ctx, h.cfg, { sender: h.sender, log: () => {} })
  await bridge.process(contactMail(contact))

  await bridge.processEvent({
    type: 'permission.asked',
    data: {
      id: 'perm-low',
      sessionID: 'session-1',
      action: 'read',
      resources: ['/work/alpha/README.md'],
      save: ['/work/alpha/README.md'],
    },
  })
  const code = decisionCode('perm-low')
  assert.ok(h.sent.some((entry) => entry.raw.includes(`X-OpenCode-Decision: ${code}`)))
  await bridge.process(contactReply(contact, {
    messageId: '<decision-reply@example.net>',
    text: `!approve ${code} once`,
  }))
  assert.deepEqual(h.permissionReplies, [{
    sessionID: 'session-1',
    requestID: 'perm-low',
    decision: 'once',
  }])
})

test('high-risk permission approval stays blocked unless explicitly enabled', async () => {
  const contact = await keyPair('contact@example.net')
  const h = harness(await keyFingerprint(contact.publicB64), {
    emailHighRiskDecisions: false,
  })
  const bridge = await createBridge(h.ctx, h.cfg, { sender: h.sender, log: () => {} })
  await bridge.process(contactMail(contact))
  await bridge.processEvent({
    type: 'permission.asked',
    data: {
      id: 'perm-high',
      sessionID: 'session-1',
      action: 'bash',
      resources: ['/etc/passwd'],
    },
  })
  const code = decisionCode('perm-high')
  const noticeIndex = h.sent.findIndex((entry) => entry.raw.includes(`X-OpenCode-Decision: ${code}`))
  assert.ok(noticeIndex >= 0)
  const texts = await sentTexts(h.sent, bridge.getIdentity())
  assert.match(texts[noticeIndex], /HIGH RISK/)
  await bridge.process(contactReply(contact, {
    messageId: '<high-risk-reply@example.net>',
    text: `!approve ${code} once`,
  }))
  assert.equal(h.permissionReplies.length, 0)
})

test('multiple-choice answers are forwarded to the GUI form responder', async () => {
  const contact = await keyPair('contact@example.net')
  const h = harness(await keyFingerprint(contact.publicB64))
  const bridge = await createBridge(h.ctx, h.cfg, {
    sender: h.sender,
    log: () => {},
    onQuestionAnswer: async (answer) => { h.questionAnswers.push(answer) },
  })
  await bridge.process(contactMail(contact))
  await bridge.processEvent({
    type: 'form.created',
    data: {
      form: {
        id: 'frm-1',
        sessionID: 'session-1',
        title: 'Choose output',
        metadata: { kind: 'question' },
        fields: [
          {
            key: 'q0',
            title: 'Format',
            type: 'string',
            options: [
              { value: 'diff', label: 'Diff' },
              { value: 'html', label: 'HTML' },
            ],
          },
        ],
      },
    },
  })
  const code = decisionCode('frm-1')
  assert.ok(h.sent.some((entry) => entry.raw.includes(`X-OpenCode-Question: ${code}`)))
  await bridge.process(contactReply(contact, {
    messageId: '<question-reply@example.net>',
    text: `!answer ${code} 2`,
  }))
  assert.deepEqual(h.questionAnswers, [{
    formID: 'frm-1',
    sessionID: 'session-1',
    answer: [{ key: 'q0', value: 'html' }],
  }])
  await bridge.confirmQuestionReply({ formID: 'frm-1', ok: true })
  assert.ok(h.sent.some((entry) => entry.raw.includes('X-OpenCode-Command: question-answered')))
})

test('watch subscriptions email completion notices and !peek reads session context', async () => {
  const contact = await keyPair('contact@example.net')
  const h = harness(await keyFingerprint(contact.publicB64), {}, {
    assistantText: 'The report is ready',
  })
  const bridge = await createBridge(h.ctx, h.cfg, { sender: h.sender, log: () => {} })
  await bridge.process(contactMail(contact))
  await bridge.process(contactReply(contact, {
    messageId: '<watch@example.net>',
    text: '!watch',
  }))
  await bridge.processEvent({
    type: 'session.execution.succeeded',
    data: { sessionID: 'session-1' },
  })
  assert.ok(h.sent.some((entry) => entry.raw.includes('X-OpenCode-Notice: success')))
  await bridge.process(contactReply(contact, {
    messageId: '<peek@example.net>',
    text: '!peek 2',
  }))
  const texts = await sentTexts(h.sent, bridge.getIdentity())
  assert.ok(texts.some((text) => text.includes('The report is ready')))
})

test('the encrypted welcome mail is sent once after establishment', async () => {
  const contact = await keyPair('contact@example.net')
  const h = harness(await keyFingerprint(contact.publicB64), {}, {
    assistantText: 'done',
  })
  const bridge = await createBridge(h.ctx, h.cfg, { sender: h.sender, log: () => {} })
  await bridge.process(contactMail(contact))
  await bridge.process(contactReply(contact, {
    messageId: '<after-welcome@example.net>',
    text: 'continue',
  }))
  const helpMails = h.sent.filter((entry) => entry.raw.includes('X-OpenCode-Command: help'))
  assert.equal(helpMails.length, 1)
})
