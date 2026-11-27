import test from 'node:test'
import assert from 'node:assert/strict'
import { setupMarkdown, setupReadiness } from '../src/setup.js'

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

test('a failed mail test blocks the handshake', () => {
  const ready = setupReadiness(settings(), status(), {
    mailTestAvailable: true, mailTestOk: false,
  })
  assert.equal(ready.next.id, 'mail')
  assert.equal(ready.canStartSecureJoin, false)
})
