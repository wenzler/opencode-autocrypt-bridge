import test from 'node:test'
import assert from 'node:assert/strict'
import plugin from '../src/index.js'

function fakeContext(storageValues, handlersOut, emitted) {
  const tools = []
  const disposals = []
  const toolApi = { add(definition) { tools.push(definition) }, async dispose() { disposals.push('tool') } }
  const registration = {
    events: {
      async emit(name, status) { emitted.push({ name, status }) },
    },
    async dispose() { disposals.push('registration') },
  }
  return {
    options: {},
    storage: {
      async get(key) { return storageValues.get(key) },
      async set(key, value) { storageValues.set(key, value) },
    },
    rpc: {
      async register(_definition, handlers) {
        handlersOut.value = handlers
        return registration
      },
    },
    tool: {
      async transform(editor) {
        editor(toolApi)
        return toolApi
      },
    },
    session: {
      async create() { return { id: 'session-1' } },
      async get({ sessionID }) {
        if (sessionID !== 'session-1') throw new Error(`Unknown session ${sessionID}`)
        return { id: sessionID, title: 'Autocrypt session', location: { directory: '/tmp' } }
      },
      async list() {
        return { data: [{ id: 'session-1', title: 'Autocrypt session', projectID: 'p1', location: { directory: '/tmp' }, time: { updated: 1 } }] }
      },
      async prompt() { return { id: 'user-message' } },
      async wait() {},
      async context() { return [] },
    },
    location: { directory: '/tmp' },
    tools,
    disposals,
  }
}

test('plugin loads unconfigured so all settings can be entered in the UI', async () => {
  const storageValues = new Map()
  const handlersOut = { value: null }
  const emitted = []
  const ctx = fakeContext(storageValues, handlersOut, emitted)

  const dispose = await plugin.setup(ctx)
  const handlers = handlersOut.value
  assert.ok(handlers, 'RPC methods register before any config exists')

  const settings = await handlers.getSettings({})
  assert.equal(settings.address, '')
  assert.equal(settings.imapPassword, '')
  assert.equal(settings.hasImapPassword, false)

  const status = await handlers.getStatus({})
  assert.equal(status.configured, false)
  assert.equal(status.running, false)
  assert.equal(status.handshake, 'unconfigured')
  assert.match(status.lastError, /pinnedContact is required/)

  await assert.rejects(() => handlers.startHandshake({}), /not configured/)

  await handlers.updateSettings({ address: 'bot@example.org', smtpPassword: 'secret' })
  const saved = await handlers.getSettings({})
  assert.equal(saved.address, 'bot@example.org')
  assert.equal(saved.smtpPassword, '')
  assert.equal(saved.hasSmtpPassword, true)

  const stillUnconfigured = await handlers.getStatus({})
  assert.equal(stillUnconfigured.configured, false)
  assert.match(stillUnconfigured.lastError, /pinnedContact is required/)
  assert.ok(emitted.some((event) => event.name === 'status' && event.status.configured === false))

  await dispose()
})

test('GUI defaults to key generation and stores hostnames without URL schemes', async () => {
  const storageValues = new Map()
  const handlersOut = { value: null }
  const ctx = fakeContext(storageValues, handlersOut, [])

  const dispose = await plugin.setup(ctx)
  const handlers = handlersOut.value

  const initial = await handlers.getSettings({})
  assert.equal(initial.generateKey, true)
  assert.equal(initial.verifyCertificate, true)
  assert.equal(initial.preferEncryptMutual, true)
  assert.equal(initial.emailDecisions, true)
  assert.equal(initial.emailHighRiskDecisions, false)
  assert.equal(initial.emailQuestions, true)
  assert.equal(initial.emailPeek, true)
  assert.equal(initial.emailTail, true)
  assert.equal(initial.emailSendFiles, true)
  assert.equal(initial.emailWatch, true)
  assert.equal(typeof handlers.rescanInbox, 'function')
  assert.equal(typeof handlers.reportQuestionReply, 'function')

  await handlers.updateSettings({
    imapHost: 'https://imap.example.org/',
    smtpHost: 'https://smtp.example.org/path',
    generateKey: false,
    emailHighRiskDecisions: true,
    emailWatch: false,
  })
  const saved = await handlers.getSettings({})
  assert.equal(saved.imapHost, 'imap.example.org')
  assert.equal(saved.smtpHost, 'smtp.example.org')
  assert.equal(saved.generateKey, false)
  assert.equal(saved.emailHighRiskDecisions, true)
  assert.equal(saved.emailWatch, false)

  await dispose()
})

test('session RPC and agent tool are registered for project awareness', async () => {
  const storageValues = new Map()
  const handlersOut = { value: null }
  const ctx = fakeContext(storageValues, handlersOut, [])

  const dispose = await plugin.setup(ctx)
  const handlers = handlersOut.value

  assert.equal(typeof handlers.listSessions, 'function')
  assert.equal(typeof handlers.bindSession, 'function')
  assert.equal(typeof handlers.createSession, 'function')
  assert.ok(ctx.tools.some((tool) => tool.name === 'autocrypt_send_file'))
  assert.ok(ctx.tools.some((tool) => tool.name === 'autocrypt_sessions'))

  const catalog = await handlers.listSessions({})
  assert.ok(Array.isArray(catalog.sessions))
  assert.ok(Array.isArray(catalog.projects))
  assert.equal(catalog.boundSessionID, '')

  const status = await handlers.getStatus({})
  assert.equal(status.sessionID, '')

  await handlers.updateSettings({
    defaultSessionID: 'ses_example',
    defaultSessionDirectory: '/tmp/project',
  })
  const saved = await handlers.getSettings({})
  assert.equal(saved.defaultSessionID, 'ses_example')
  assert.equal(saved.defaultSessionDirectory, '/tmp/project')

  await dispose()
})

test('reloading the plugin keeps RPC registered while replacing the mail bridge', async () => {
  const firstOut = { value: null }
  const firstCtx = fakeContext(new Map(), firstOut, [])
  const firstDispose = await plugin.setup(firstCtx)
  const firstHandlers = firstOut.value
  assert.ok(firstHandlers)

  // A hot reload or GUI attach creates a second setup in the same process.
  const secondOut = { value: null }
  const secondCtx = fakeContext(new Map(), secondOut, [])
  const secondDispose = await plugin.setup(secondCtx)

  assert.notStrictEqual(secondOut.value, firstHandlers, 'new instance owns the active handlers')
  assert.deepEqual(firstCtx.disposals, [], 'reload does not tear down the RPC registration')
  assert.ok(await secondOut.value.getStatus({}), 'RPC stays callable after the reload')

  await firstDispose()
  assert.equal(firstCtx.disposals.length, 2, 'late cleanup of the old instance is a no-op')
  await secondDispose()
})
