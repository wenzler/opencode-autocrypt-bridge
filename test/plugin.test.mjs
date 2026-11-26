import test from 'node:test'
import assert from 'node:assert/strict'
import plugin from '../src/index.js'

function fakeContext(storageValues, handlersOut, emitted) {
  const toolApi = { add() {}, async dispose() {} }
  const registration = {
    events: {
      async emit(name, status) { emitted.push({ name, status }) },
    },
    async dispose() {},
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
      async prompt() { return { id: 'user-message' } },
      async wait() {},
      async context() { return [] },
    },
    location: { directory: '/tmp' },
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
  assert.equal(typeof handlers.rescanInbox, 'function')

  await handlers.updateSettings({
    imapHost: 'https://imap.example.org/',
    smtpHost: 'https://smtp.example.org/path',
    generateKey: false,
  })
  const saved = await handlers.getSettings({})
  assert.equal(saved.imapHost, 'imap.example.org')
  assert.equal(saved.smtpHost, 'smtp.example.org')
  assert.equal(saved.generateKey, false)

  await dispose()
})
