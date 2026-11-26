import { readFileSync } from 'node:fs'
import path from 'node:path'
import { normalizeFingerprint, parseInviteUrl, publicKeyToBase64, redactInviteUrl } from './headers.js'

const PREFIX = 'opencode-autocrypt-bridge:'

function pick(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== '') return value
  }
  return values.length ? values[values.length - 1] : undefined
}

function integer(value, fallback) {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback
}

function boolean(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback
  if (typeof value === 'boolean') return value
  return /^(1|true|yes|on)$/i.test(String(value))
}

/** Keep IMAP/SMTP fields as hostnames even if a form adds a URL scheme. */
export function normalizeHost(value) {
  let host = String(value ?? '').trim()
  host = host.replace(/^[a-z][a-z\d+.-]*:\/\//i, '')
  host = host.replace(/^.*@/, '')
  host = host.split(/[/?#]/, 1)[0]
  return host.toLowerCase()
}

/**
 * Configuration comes from plugin options first, then environment variables.
 * This mirrors the pattern used by opencode-email-notify / opencode-email-sync.
 */
export function loadConfig(options = {}, env = process.env) {
  const get = (key, envKey, fallback) => pick(options[key], env[envKey], fallback)

  const address = String(get('address', 'AC_ADDRESS', '')).trim().toLowerCase()
  const displayName = String(get('displayName', 'AC_DISPLAY_NAME', address.split('@')[0] || 'opencode'))
  const imapUser = String(get('imapUser', 'AC_IMAP_USER', address))
  const smtpUser = String(get('smtpUser', 'AC_SMTP_USER', address))

  // Invite URLs are only a convenience for filling the pinned gate locally.
  // They never enable an invite protocol; i=/s= tokens are discarded.
  const inviteUrl = String(pick(options.inviteUrl, env.AC_INVITE_URL, ''))
  let invite
  if (inviteUrl) {
    try {
      invite = parseInviteUrl(inviteUrl)
    } catch (error) {
      throw new Error(`${PREFIX} invalid invite URL: ${error.message}`)
    }
  }

  // The pinned gate is mandatory. Invite-based modes may supply the pinned
  // values; explicit pinned settings still win and must agree.
  const pinnedContact = String(get('pinnedContact', 'AC_PINNED_CONTACT', invite?.address || '')).trim().toLowerCase()
  if (!pinnedContact) {
    throw new Error(`${PREFIX} pinnedContact is required; it is the only address allowed to drive OpenCode`)
  }
  const explicitFingerprint = String(pick(
    options.pinnedFingerprint,
    options.pinnedContactFingerprint,
    env.AC_PINNED_FINGERPRINT,
    env.AC_PINNED_CONTACT_FINGERPRINT,
    '',
  ))
  const pinnedFingerprintSource = explicitFingerprint || invite?.fingerprint || ''
  let pinnedKeySource = String(get('pinnedContactKey', 'AC_PINNED_CONTACT_KEY', ''))
  const pinnedKeyFile = String(get('pinnedContactKeyFile', 'AC_PINNED_CONTACT_KEY_FILE', ''))
  if (pinnedKeyFile && !pinnedKeySource) {
    try {
      pinnedKeySource = readFileSync(pinnedKeyFile, 'utf8')
    } catch (error) {
      throw new Error(`${PREFIX} cannot read AC_PINNED_CONTACT_KEY_FILE: ${error.message}`)
    }
  }
  if (!pinnedFingerprintSource && !pinnedKeySource) {
    throw new Error(`${PREFIX} pinnedContact requires pinnedFingerprint (or pinnedContactKey)`)
  }
  const pinnedFingerprint = normalizeFingerprint(pinnedFingerprintSource)
  const pinnedKeyB64 = publicKeyToBase64(pinnedKeySource)

  if (invite) {
    if (invite.fingerprint !== pinnedFingerprint) {
      throw new Error(`${PREFIX} invite fingerprint does not match pinnedFingerprint`)
    }
    if (invite.address && invite.address !== pinnedContact) {
      throw new Error(`${PREFIX} invite address does not match pinnedContact`)
    }
  }

  const cfg = {
    address,
    displayName,
    imap: {
      host: normalizeHost(get('imapHost', 'AC_IMAP_HOST', '')),
      port: integer(get('imapPort', 'AC_IMAP_PORT'), 993),
      security: String(get('imapSecurity', 'AC_IMAP_SECURITY', 'tls')).toLowerCase(),
      user: imapUser,
      password: String(get('imapPassword', 'AC_IMAP_PASSWORD', '')),
      mailbox: String(get('imapMailbox', 'AC_IMAP_MAILBOX', 'INBOX')),
      pollIntervalMs: integer(get('pollIntervalMs', 'AC_POLL_INTERVAL_MS'), 30_000),
      verifyCertificate: boolean(get('verifyCertificate', 'AC_VERIFY_CERTIFICATE'), true),
    },
    smtp: {
      host: normalizeHost(get('smtpHost', 'AC_SMTP_HOST', '')),
      port: integer(get('smtpPort', 'AC_SMTP_PORT'), 465),
      security: String(get('smtpSecurity', 'AC_SMTP_SECURITY', 'tls')).toLowerCase(),
      user: smtpUser,
      password: String(get('smtpPassword', 'AC_SMTP_PASSWORD', '')),
      verifyCertificate: boolean(get('verifyCertificate', 'AC_VERIFY_CERTIFICATE'), true),
    },
    allowedContacts: [pinnedContact],
    pinned: {
      contact: pinnedContact,
      fingerprint: pinnedFingerprint,
      // Optional bootstrap key: it must match the pinned fingerprint and lets
      // the first encrypted acknowledgement be sent before key learning.
      keyB64: pinnedKeyB64,
      requireEncrypted: boolean(get('requireEncrypted', 'AC_REQUIRE_ENCRYPTED'), false),
      inviteUrl: redactInviteUrl(inviteUrl),
      invite,
    },
    session: {
      defaultID: String(get('defaultSessionID', 'AC_SESSION_ID', '')).trim(),
      defaultDirectory: String(get('defaultSessionDirectory', 'AC_SESSION_DIRECTORY', '')).trim(),
    },
    // Email remote controls. High-risk approvals stay off by default: the
    // bridge must never become a remote shell.
    remote: {
      decisions: boolean(get('emailDecisions', 'AC_EMAIL_DECISIONS'), true),
      highRiskDecisions: boolean(get('emailHighRiskDecisions', 'AC_EMAIL_HIGH_RISK_DECISIONS'), false),
      questions: boolean(get('emailQuestions', 'AC_EMAIL_QUESTIONS'), true),
      peek: boolean(get('emailPeek', 'AC_EMAIL_PEEK'), true),
      tail: boolean(get('emailTail', 'AC_EMAIL_TAIL'), true),
      sendFiles: boolean(get('emailSendFiles', 'AC_EMAIL_SEND_FILES'), true),
      watch: boolean(get('emailWatch', 'AC_EMAIL_WATCH'), true),
    },
    maxMessageBytes: integer(get('maxMessageBytes', 'AC_MAX_MESSAGE_BYTES'), 20 * 1024 * 1024),
    maxAttachmentBytes: integer(get('maxAttachmentBytes', 'AC_MAX_ATTACHMENT_BYTES'), 10 * 1024 * 1024),
    attachmentDir: path.resolve(String(get('attachmentDir', 'AC_ATTACHMENT_DIR', path.join('.opencode', 'autocrypt-attachments')))),
    key: {
      privateKeyArmored: String(get('privateKeyArmored', 'AC_PRIVATE_KEY', '')),
      privateKeyFile: String(get('privateKeyFile', 'AC_PRIVATE_KEY_FILE', '')),
      passphrase: String(get('keyPassphrase', 'AC_KEY_PASSPHRASE', '')),
      generate: boolean(get('generateKey', 'AC_GENERATE_KEY'), true),
      preferEncryptMutual: boolean(get('preferEncryptMutual', 'AC_PREFER_ENCRYPT_MUTUAL'), true),
    },
  }

  const missing = []
  if (!cfg.address) missing.push('address')
  if (!cfg.imap.host) missing.push('imapHost')
  if (!cfg.imap.password) missing.push('imapPassword')
  if (!cfg.smtp.host) missing.push('smtpHost')
  if (!cfg.smtp.password) missing.push('smtpPassword')
  if (missing.length) {
    throw new Error(`${PREFIX} missing configuration: ${missing.join(', ')}`)
  }
  if (!['tls', 'starttls', 'plain'].includes(cfg.imap.security)) {
    throw new Error(`${PREFIX} imapSecurity must be tls, starttls or plain`)
  }
  if (!['tls', 'starttls', 'plain'].includes(cfg.smtp.security)) {
    throw new Error(`${PREFIX} smtpSecurity must be tls, starttls or plain`)
  }
  return cfg
}
