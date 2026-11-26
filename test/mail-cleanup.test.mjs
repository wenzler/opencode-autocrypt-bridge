import test from 'node:test'
import assert from 'node:assert/strict'
import { deleteProcessedMessage } from '../src/mail.js'

test('processed messages are expunged by UID', async () => {
  const calls = []
  const client = {
    async messageDelete(range, options) {
      calls.push([range, options])
      return true
    },
  }
  assert.equal(await deleteProcessedMessage(client, 42, () => {}), true)
  assert.deepEqual(calls, [[42, { uid: true }]])
})

test('a failed expunge is logged and does not break processing', async () => {
  const logs = []
  const client = {
    async messageDelete() { throw new Error('EXPUNGE denied') },
  }
  assert.equal(await deleteProcessedMessage(client, 7, (message) => logs.push(message)), false)
  assert.match(logs.join('\n'), /UID 7.*EXPUNGE denied/)
})
