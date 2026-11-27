import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { COMMAND_ALIASES, COMMAND_SPECS } from '../src/commands.js'
import { parseSessionCommand } from '../src/session.js'
import { redactInviteUrl } from '../src/headers.js'
import { loadConfig } from '../src/config.js'
import { BridgeRpc } from '../src/rpc.js'
import {
  SETTING_KEYS,
  SETTINGS_INPUT_PROPERTIES,
  SETTINGS_OUTPUT_PROPERTIES,
  UI_DEFAULTS,
  applySettingValues,
  settingsView,
} from '../src/settings.js'
import { setupReadiness } from '../src/setup.js'

const FPR = '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE'
const INVITE = `OPENPGP4FPR:${FPR}#a=contact%40example.net&n=Contact&s=OLD_AUTH&i=42&v=3`

test('every advertised command alias is accepted by the parser', () => {
  for (const spec of COMMAND_SPECS) {
    for (const alias of spec.names.slice(1)) {
      assert.equal(COMMAND_ALIASES[alias], spec.names[0], `${alias} maps to ${spec.names[0]}`)
      assert.equal(parseSessionCommand(`!${alias} arg`).command, spec.names[0], `!${alias} parses`)
    }
  }
  assert.equal(parseSessionCommand('!output').command, 'peek')
})

test('one settings registry drives the RPC schema, stored values and GUI defaults', () => {
  assert.deepEqual(Object.keys(SETTINGS_INPUT_PROPERTIES), SETTING_KEYS)
  assert.deepEqual(
    Object.keys(SETTINGS_OUTPUT_PROPERTIES),
    [...SETTING_KEYS, 'hasImapPassword', 'hasSmtpPassword', 'hasPinnedContactKey', 'hasSecureJoinAuth', 'hasPrivateKey', 'hasKeyPassphrase'],
  )
  const methods = BridgeRpc.methods
  assert.deepEqual(Object.keys(methods.updateSettings.input.properties), SETTING_KEYS)
  assert.equal(methods.getSettings.output.properties.hasSecureJoinAuth.type, 'boolean')
  const gui = readFileSync(fileURLToPath(new URL('../src/gui.tsx', import.meta.url)), 'utf8')
  assert.match(gui, /import \{ SETTING_KEYS, SETTING_SPECS, UI_DEFAULTS \} from "\.\/settings\.js"/)
  assert.match(gui, /Object\.fromEntries\(SETTING_KEYS\.map/)
  assert.doesNotMatch(gui, /const defaults = \{/)
})

test('the mail and attachment size limits survive config reuse', () => {
  const cfg = loadConfig({
    address: 'bot@example.org', imapHost: 'imap.example.org', imapPassword: 'p',
    smtpHost: 'smtp.example.org', smtpPassword: 'p', pinnedContact: 'contact@example.net',
    pinnedFingerprint: FPR,
  }, { AC_MAX_MESSAGE_BYTES: '12345', AC_MAX_ATTACHMENT_BYTES: '2345' })
  assert.equal(cfg.maxMessageBytes, 12345)
  assert.equal(cfg.maxAttachmentBytes, 2345)
})

test('a redacted invite URL keeps the stored secret; a new secret URL replaces it', () => {
  const stored = { inviteUrl: INVITE }
  const redacted = redactInviteUrl(INVITE)
  assert.doesNotMatch(redacted, /OLD_AUTH|OLD_AUTH|i=42/)
  assert.deepEqual(applySettingValues(stored, { inviteUrl: redacted }), stored)
  const updated = applySettingValues(stored, { inviteUrl: INVITE.replace('OLD_AUTH', 'NEW_AUTH') })
  assert.match(updated.inviteUrl, /NEW_AUTH/)
  assert.doesNotMatch(updated.inviteUrl, /OLD_AUTH/)
  const view = settingsView(stored)
  assert.equal(view.hasSecureJoinAuth, true)
  assert.equal(view.inviteUrl, redacted)
  assert.equal(view.imapPassword, '')
})

test('percent-encoded invite secrets are redacted and preserved like literal ones', () => {
  const stored = { inviteUrl: `OPENPGP4FPR:${FPR}#a=contact%40example.net&v=3&%73=OLD_AUTH&%69=42` }
  const redacted = redactInviteUrl(stored.inviteUrl)
  assert.doesNotMatch(redacted, /OLD_AUTH|42/)
  assert.deepEqual(applySettingValues(stored, { inviteUrl: redacted }), stored)
  const updated = applySettingValues(stored, {
    inviteUrl: stored.inviteUrl.replace('OLD_AUTH', 'NEW_AUTH'),
  })
  assert.match(updated.inviteUrl, /NEW_AUTH/)
  assert.doesNotMatch(updated.inviteUrl, /OLD_AUTH/)
  const view = settingsView(stored)
  assert.equal(view.hasSecureJoinAuth, true)
  assert.equal(view.inviteUrl, redacted)
})

test('Autocrypt key confirmation does not claim SecureJoin verification', () => {
  const values = {
    address: 'bot@example.org', imapHost: 'imap.example.org', smtpHost: 'smtp.example.org',
    hasImapPassword: true, hasSmtpPassword: true, pinnedContact: 'contact@example.net',
    pinnedFingerprint: FPR,
  }
  const result = {
    configured: true, running: true, remoteMode: 'autocrypt', pinnedContact: 'contact@example.net',
    pinnedFingerprint: FPR, established: true, verified: false, learnedFingerprint: FPR,
  }
  const autocrypt = setupReadiness(values, result, {})
  assert.equal(autocrypt.established, true)
  assert.equal(autocrypt.learned, true)
  assert.equal(autocrypt.secureJoinVerified, false)
  assert.equal(autocrypt.verified, true)
  assert.equal(autocrypt.next.id, 'done')
  const securejoin = setupReadiness(
    { ...values, remoteMode: 'securejoin', secureJoinAuth: 'AUTH' },
    { ...result, remoteMode: 'securejoin', secureJoin: { hasAuth: true } },
    {},
  )
  assert.equal(securejoin.verified, false)
  assert.equal(securejoin.next.id, 'verify')
})
