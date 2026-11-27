import test from 'node:test'
import assert from 'node:assert/strict'
import { armorToBase64, autocryptHeader, unfold, parseAutocryptHeader, parseInviteUrl, redactInviteUrl } from '../src/headers.js'
import { buildInnerMime, buildPgpMime, buildMail, parseRawHeaders, contentTypeOf } from '../src/mime.js'
import { loadConfig, normalizeHost } from '../src/config.js'

test('autocrypt header folds keydata and unfolds cleanly', () => {
  const key = 'A'.repeat(200)
  const header = autocryptHeader('bot@example.org', key, true)
  assert.ok(header.startsWith('addr=bot@example.org; prefer-encrypt=mutual; keydata='))
  assert.ok(header.includes('\r\n '))
  assert.equal(unfold(header).endsWith(`keydata=${key}`), true)
})

test('armorToBase64 drops the CRC24 checksum line', () => {
  const armored = [
    '-----BEGIN PGP PUBLIC KEY BLOCK-----',
    '',
    'QUJDRA==',
    '=abcd',
    '-----END PGP PUBLIC KEY BLOCK-----',
  ].join('\n')
  assert.equal(armorToBase64(armored), 'QUJDRA==')
})

test('autocrypt header parses peer key and mutual preference', () => {
  const header = autocryptHeader('peer@example.net', 'QUJDRA==', true)
  const parsed = parseAutocryptHeader(header, 'peer@example.net')
  assert.deepEqual(parsed, { addr: 'peer@example.net', keydata: 'QUJDRA==', preferEncrypt: true })
  assert.equal(parseAutocryptHeader(header, 'other@example.net'), undefined)
})

test('inner MIME carries text and a jpeg attachment', () => {
  const mime = buildInnerMime({
    text: 'hello',
    attachments: [{ filename: 'photo.jpg', contentType: 'image/jpeg', content: Buffer.from([1, 2, 3]) }],
  })
  const entity = mime.entity.toString('utf8')
  assert.match(entity, /Content-Type: multipart\/mixed; boundary=/)
  assert.match(entity, /Content-Type: text\/plain; charset=utf-8/)
  assert.match(entity, /Content-Type: image\/jpeg; name="photo.jpg"/)
  assert.doesNotMatch(entity, /image\/jpeg; charset/)
  assert.match(entity, /Content-Disposition: attachment; filename="photo.jpg"/)
  assert.equal(Buffer.from('aGVsbG8=', 'base64').toString('utf8'), 'hello')
})

test('PGP/MIME wrapper has both required parts', () => {
  const wrapper = buildPgpMime('-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----')
  const text = wrapper.body.toString('utf8')
  assert.match(wrapper.contentType, /multipart\/encrypted/)
  assert.match(text, /Content-Type: application\/pgp-encrypted/)
  assert.match(text, /Version: 1/)
  assert.match(text, /Content-Type: application\/octet-stream/)
})

test('outer mail always keeps Autocrypt and the client marker, with no invite-protocol headers', () => {
  const cfg = {
    address: 'bot@example.org',
    displayName: 'Bridge',
    key: { preferEncryptMutual: true },
  }
  const raw = buildMail({
    cfg,
    to: 'me@example.net',
    subject: 'Message from Bridge',
    messageId: '123@example.org',
    publicB64: 'QUJD',
    inReplyTo: '<prev@example.net>',
    contentType: 'text/plain',
    body: Buffer.from('hi'),
  })
  const headers = parseRawHeaders(raw)
  assert.equal(headers.get('in-reply-to'), '<prev@example.net>')
  assert.equal(headers.get('x-opencode-autocrypt-bridge'), '1')
  assert.equal(headers.get('chat-version'), '1.0')
  assert.equal(headers.get('secure-join'), undefined)
  assert.equal(headers.get('secure-join-auth'), undefined)
  assert.match(headers.get('autocrypt'), /keydata=QUJD/)
})

test('content type detection for requested formats', () => {
  assert.equal(contentTypeOf('photo.jpg'), 'image/jpeg')
  assert.equal(contentTypeOf('page.html'), 'text/html')
  assert.equal(contentTypeOf('unknown.bin'), 'application/octet-stream')
})

const baseEnv = {
  AC_ADDRESS: 'bot@example.org',
  AC_IMAP_HOST: 'imap.example.org',
  AC_IMAP_PASSWORD: 'secret',
  AC_SMTP_HOST: 'smtp.example.org',
  AC_SMTP_PASSWORD: 'secret',
}

test('host fields accept hostnames but strip URL schemes and paths', () => {
  assert.equal(normalizeHost('https://imap.example.org:993/'), 'imap.example.org:993')
  assert.equal(normalizeHost(' IMAP.Example.Org '), 'imap.example.org')
  const cfg = loadConfig({
    address: 'bot@example.org',
    imapHost: 'https://imap.example.org/',
    imapPassword: 'secret',
    smtpHost: 'http://smtp.example.org:587/path',
    smtpPassword: 'secret',
    pinnedContact: 'me@example.net',
    pinnedFingerprint: '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE',
  }, {})
  assert.equal(cfg.imap.host, 'imap.example.org')
  assert.equal(cfg.smtp.host, 'smtp.example.org:587')
})

test('config reads env and requires a pinned gate', () => {
  const cfg = loadConfig({}, {
    ...baseEnv,
    AC_PINNED_CONTACT: 'me@example.net',
    AC_PINNED_FINGERPRINT: '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE',
  })
  assert.equal(cfg.address, 'bot@example.org')
  assert.equal(cfg.imap.port, 993)
  assert.equal(cfg.smtp.port, 465)
  assert.deepEqual(cfg.allowedContacts, ['me@example.net'])
  assert.throws(() => loadConfig({}, {}), /pinnedContact is required/)
  assert.throws(() => loadConfig({}, { ...baseEnv }), /pinnedContact is required/)
  assert.throws(() => loadConfig({}, { ...baseEnv, AC_PINNED_CONTACT: 'me@example.net' }), /requires pinnedFingerprint/)
})

test('deleteAfterRead is opt-in through settings or env', () => {
  const values = {
    address: 'bot@example.org',
    imapHost: 'imap.example.org',
    imapPassword: 'secret',
    smtpHost: 'smtp.example.org',
    smtpPassword: 'secret',
    pinnedContact: 'me@example.net',
    pinnedFingerprint: '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE',
  }
  assert.equal(loadConfig(values, {}).imap.deleteAfterRead, false)
  assert.equal(loadConfig({ ...values, deleteAfterRead: true }, {}).imap.deleteAfterRead, true)
  const fromEnv = loadConfig({}, {
    ...baseEnv,
    AC_PINNED_CONTACT: 'me@example.net',
    AC_PINNED_FINGERPRINT: '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE',
    AC_DELETE_AFTER_READ: 'on',
  })
  assert.equal(fromEnv.imap.deleteAfterRead, true)
})

test('progressive replies default on with a clamped interval', () => {
  const values = {
    address: 'bot@example.org',
    imapHost: 'imap.example.org',
    imapPassword: 'secret',
    smtpHost: 'smtp.example.org',
    smtpPassword: 'secret',
    pinnedContact: 'me@example.net',
    pinnedFingerprint: '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE',
  }
  assert.equal(loadConfig(values, {}).remote.progress, true)
  assert.equal(loadConfig(values, {}).remote.progressIntervalMs, 20000)
  const fast = loadConfig({ ...values, emailProgressIntervalMs: 1000 }, {})
  assert.equal(fast.remote.progressIntervalMs, 5000)
  const fromEnv = loadConfig({}, {
    ...baseEnv,
    AC_PINNED_CONTACT: 'me@example.net',
    AC_PINNED_FINGERPRINT: '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE',
    AC_EMAIL_PROGRESS: 'off',
    AC_EMAIL_PROGRESS_INTERVAL_MS: '30000',
  })
  assert.equal(fromEnv.remote.progress, false)
  assert.equal(fromEnv.remote.progressIntervalMs, 30000)
})

const fingerprint = '669AE77C1D829C65258FC4F8F220CFCAEAA9A4CE'

test('pinned fingerprint can be pasted from an invite-style URI', () => {
  const link = `#${fingerprint}&v=3&i=abc&s=def&a=me%40example.net`
  const cfg = loadConfig({}, {
    ...baseEnv,
    AC_PINNED_CONTACT: 'me@example.net',
    AC_PINNED_FINGERPRINT: link,
  })
  assert.equal(cfg.pinned.fingerprint, fingerprint)
  assert.equal(cfg.pinned.keyB64, '')
})

test('invite URL parsing exposes pin fields and the SecureJoin auth code', () => {
  const url = `https://example.org/#${fingerprint}&v=3&i=NJFZBXGwoQh6B_kDQlJrj2nP&s=secret&a=me%40example.net&n=Me&r=relay%40example.net`
  const invite = parseInviteUrl(url)
  assert.deepEqual(invite, {
    fingerprint,
    address: 'me@example.net',
    name: 'Me',
    version: '3',
    auth: 'secret',
    inviteNumber: 'NJFZBXGwoQh6B_kDQlJrj2nP',
    relays: 'relay@example.net',
    groupID: '',
    groupName: '',
    broadcastName: '',
  })
  assert.equal(parseInviteUrl(`OPENPGP4FPR:${fingerprint}%23v=3&s=secret`).fingerprint, fingerprint)
  assert.equal(parseInviteUrl(`#${fingerprint}&a=me%40example.net`).address, 'me@example.net')
  assert.equal(parseInviteUrl(`#${fingerprint}&s=secret`).version, '')
  assert.equal(parseInviteUrl(`#${fingerprint}&j=legacy`).inviteNumber, 'legacy')
  const encodedNames = parseInviteUrl(`#${fingerprint}&%73=encoded-auth&%69=encoded-invite&v=3`)
  assert.equal(encodedNames.auth, 'encoded-auth')
  assert.equal(encodedNames.inviteNumber, 'encoded-invite')
  assert.throws(() => parseInviteUrl('#nope&a=me%40example.net'), /Invalid OpenPGP fingerprint/)
})

test('invite URL redaction hides secrets and is stable', () => {
  const url = `https://example.org/#${fingerprint}&v=3&i=NJFZBXGwoQh6B_kDQlJrj2nP&s=secret&a=me%40example.net&n=Me`
  const redacted = redactInviteUrl(url)
  assert.equal(redacted, `https://example.org/#${fingerprint}&v=3&a=me%40example.net&n=Me`)
  assert.equal(redactInviteUrl(redacted), redacted)
  assert.doesNotMatch(redacted, /secret|NJFZBXGwoQh6B_kDQlJrj2nP/)
  const encoded = redactInviteUrl(`OPENPGP4FPR:${fingerprint}%23v=3&s=secret`)
  assert.equal(encoded, `OPENPGP4FPR:${fingerprint}#v=3`)
  assert.doesNotMatch(encoded, /secret/)
  assert.equal(redactInviteUrl(encoded), encoded)
})

test('invite URL redaction decodes percent-encoded secret names', () => {
  const url = `https://example.org/#${fingerprint}&v=3&%73=auth&%69=invite&%6A=legacy&%61=keep%40example.net`
  const redacted = redactInviteUrl(url)
  assert.equal(redacted, `https://example.org/#${fingerprint}&v=3&%61=keep%40example.net`)
  assert.doesNotMatch(redacted, /auth|invite|legacy/)
  assert.equal(redactInviteUrl(redacted), redacted)

  const openpgp = redactInviteUrl(`OPENPGP4FPR:${fingerprint}%23%53=AUTH&n=Me`)
  assert.equal(openpgp, `OPENPGP4FPR:${fingerprint}#n=Me`)
  assert.doesNotMatch(openpgp, /AUTH/)
  assert.equal(redactInviteUrl(openpgp), openpgp)

  assert.equal(redactInviteUrl(`#${fingerprint}&%73omething=keep`), `#${fingerprint}&%73omething=keep`)
})

test('invite URL must agree with the pinned gate', () => {
  const env = {
    ...baseEnv,
    AC_PINNED_CONTACT: 'me@example.net',
    AC_PINNED_FINGERPRINT: fingerprint,
  }
  assert.equal(loadConfig({}, { ...env, AC_INVITE_URL: `#${fingerprint}&a=me%40example.net` }).pinned.invite.address, 'me@example.net')
  assert.throws(
    () => loadConfig({}, { ...env, AC_INVITE_URL: `#${'1'.repeat(40)}&a=me%40example.net` }),
    /invite fingerprint does not match/,
  )
  assert.throws(
    () => loadConfig({}, { ...env, AC_INVITE_URL: `#${fingerprint}&a=other%40example.net` }),
    /invite address does not match/,
  )
})

test('config keeps auth for SecureJoin while redacting the displayed invite URL', () => {
  const cfg = loadConfig({}, {
    ...baseEnv,
    AC_PINNED_CONTACT: 'me@example.net',
    AC_INVITE_URL: `#${fingerprint}&v=3&i=NJFZBXGwoQh6B_kDQlJrj2nP&s=secret&a=me%40example.net`,
  })
  assert.equal(cfg.pinned.contact, 'me@example.net')
  assert.equal(cfg.pinned.fingerprint, fingerprint)
  assert.equal(cfg.pinned.inviteUrl, `#${fingerprint}&v=3&a=me%40example.net`)
  assert.equal(cfg.pinned.invite.auth, 'secret')
  assert.equal(cfg.pinned.secureJoin.auth, 'secret')
  assert.equal(cfg.pinned.secureJoin.version, '3')
  assert.equal(cfg.pinned.mode, undefined)

  const encoded = loadConfig({}, {
    ...baseEnv,
    AC_PINNED_CONTACT: 'me@example.net',
    AC_INVITE_URL: `#${fingerprint}&v=3&%73=encoded-secret&a=me%40example.net`,
  })
  assert.equal(encoded.pinned.inviteUrl, `#${fingerprint}&v=3&a=me%40example.net`)
  assert.equal(encoded.pinned.invite.auth, 'encoded-secret')
  assert.equal(encoded.pinned.secureJoin.auth, 'encoded-secret')
})

test('optional pinned key is still accepted alongside the fingerprint', () => {
  const armored = [
    '-----BEGIN PGP PUBLIC KEY BLOCK-----',
    '',
    'mQINBFo=',
    '-----END PGP PUBLIC KEY BLOCK-----',
  ].join('\n')
  const cfg = loadConfig({}, {
    ...baseEnv,
    AC_PINNED_CONTACT: 'me@example.net',
    AC_PINNED_FINGERPRINT: fingerprint,
    AC_PINNED_CONTACT_KEY: armored,
  })
  assert.equal(cfg.pinned.fingerprint, fingerprint)
  assert.equal(cfg.pinned.keyB64, 'mQINBFo=')

  // A key alone is not enough: the explicit pin is mandatory.
  assert.throws(() => loadConfig({}, {
    ...baseEnv,
    AC_PINNED_CONTACT: 'me@example.net',
    AC_PINNED_CONTACT_KEY: 'QUJDRA==',
  }), /requires pinnedFingerprint/)
})
