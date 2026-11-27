import test from 'node:test'
import assert from 'node:assert/strict'
import { mailTestCurrent, mailTestKey, secureJoinProgress, setupMarkdown, setupReadiness } from '../src/setup.js'

const FPR = '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE'

const settings = (overrides = {}) => ({
  address: 'bot@example.org',
  imapHost: 'imap.example.org',
  smtpHost: 'smtp.example.org',
  hasImapPassword: true,
  hasSmtpPassword: true,
  remoteMode: 'securejoin',
  pinnedContact: 'contact@example.net',
  pinnedFingerprint: FPR,
  secureJoinAuth: 'AUTHCODE',
  ...overrides,
})

const status = (overrides = {}) => ({
  configured: true,
  running: true,
  remoteMode: 'securejoin',
  pinnedContact: 'contact@example.net',
  pinnedFingerprint: FPR,
  secureJoin: { hasAuth: true },
  verified: false,
  ...overrides,
})

test('readiness walks through mail, pin, auth, apply and verify', () => {
  const unconfigured = setupReadiness(settings({ address: '', imapHost: '', smtpHost: '' }), {
    configured: false, running: false, pinnedContact: '', pinnedFingerprint: '', secureJoin: {},
  }, { mailTestAvailable: true, mailTestOk: true })
  assert.equal(unconfigured.next.id, 'mail')
  assert.equal(unconfigured.canStartSecureJoin, false)

  const mailOnly = setupReadiness(settings({
    pinnedContact: '', pinnedFingerprint: '', secureJoinAuth: '', hasSecureJoinAuth: false,
  }), status({
    configured: false, running: false, pinnedContact: '', pinnedFingerprint: '', secureJoin: {},
  }), { mailTestAvailable: true, mailTestOk: true })
  assert.equal(mailOnly.next.id, 'pin')

  const notApplied = setupReadiness(settings(), status({ configured: false, running: false }), {
    mailTestAvailable: true, mailTestOk: true,
  })
  assert.equal(notApplied.next.id, 'apply')
  assert.equal(notApplied.canStartSecureJoin, false)

  const applied = setupReadiness(settings(), status(), {
    mailTestAvailable: true, mailTestOk: true,
  })
  assert.equal(applied.next.id, 'verify')
  assert.equal(applied.canStartSecureJoin, true)

  const verified = setupReadiness(settings(), status({ verified: true }), {
    mailTestAvailable: true, mailTestOk: true,
  })
  assert.equal(verified.next.id, 'done')
  assert.equal(verified.canStartSecureJoin, false)
  assert.match(setupMarkdown(verified), /\[x\] \*\*SecureJoin verified\*\*/)
})

test('autocrypt mode does not require an invite auth code', () => {
  const ready = setupReadiness(settings({
    remoteMode: 'autocrypt',
    secureJoinAuth: '',
    hasSecureJoinAuth: false,
  }), status({ remoteMode: 'autocrypt', secureJoin: {} }), {
    mailTestAvailable: true, mailTestOk: true,
  })
  assert.equal(ready.mode, 'autocrypt')
  assert.equal(ready.steps.some((step) => step.id === 'auth'), false)
  assert.equal(ready.canStartHandshake, true)
  assert.equal(ready.canStartSecureJoin, false)
})

test('SecureJoin progress shows each wire step and pending state', () => {
  const sent = secureJoinProgress({ secureJoin: { status: 'request-sent', address: 'contact@example.net' } })
  assert.equal(sent.pending, true)
  assert.match(sent.markdown, /\[x\] Sent `vc-request-pubkey` to contact@example\.net/)
  assert.match(sent.markdown, /\[ \] Received signed `vc-pubkey`/)

  const auth = secureJoinProgress({ secureJoin: { status: 'auth-sent' } })
  assert.equal(auth.pending, true)
  assert.match(auth.markdown, /\[x\] Received signed `vc-pubkey`/)
  assert.match(auth.markdown, /\[x\] Sent encrypted `vc-request-with-auth`/)

  const done = secureJoinProgress({ secureJoin: { status: 'verified' } })
  assert.equal(done.verified, true)
  assert.equal(done.pending, false)
  assert.match(done.markdown, /\[x\] Received `vc-contact-confirm` — verified/)

  const cancelled = secureJoinProgress({ secureJoin: { status: 'cancelled' } })
  assert.equal(cancelled.cancelled, true)
  assert.match(cancelled.markdown, /Cancelled/)
})

test('a failed mail test blocks the handshake', () => {
  const ready = setupReadiness(settings(), status(), {
    mailTestAvailable: true, mailTestOk: false,
  })
  assert.equal(ready.next.id, 'mail')
  assert.equal(ready.canStartSecureJoin, false)
})

test('a running bridge with unchanged saved mail values counts as tested after reload', () => {
  const current = settings()
  const key = mailTestKey(current)
  assert.equal(mailTestCurrent(current, status(), null, key), true)
  assert.equal(setupReadiness(current, status(), {
    mailTestAvailable: true, mailTestOk: mailTestCurrent(current, status(), null, key),
  }).next.id, 'verify')
})

test('editing any mail field re-locks setup after reload', () => {
  const current = settings()
  const appliedKey = mailTestKey(current)
  const edited = settings({ smtpHost: 'smtp.changed.example.org' })
  const valid = mailTestCurrent(edited, status(), null, appliedKey)
  assert.equal(valid, false)
  assert.equal(setupReadiness(edited, status(), {
    mailTestAvailable: true, mailTestOk: valid,
  }).next.id, 'mail')
})

test('an in-session test still counts for the exact displayed values', () => {
  const current = settings()
  const key = mailTestKey(current)
  assert.equal(mailTestCurrent(current, status({ running: false }), { ok: true, key }, ''), true)
  assert.equal(mailTestCurrent(settings({ imapHost: 'other.example.org' }), status(), { ok: true, key }, ''), false)
})
