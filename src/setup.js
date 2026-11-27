import { normalizeFingerprint } from './headers.js'

function safeFingerprint(value) {
  try {
    return normalizeFingerprint(value)
  } catch {
    return ''
  }
}

const MAIL_TEST_FIELDS = [
  'address', 'imapHost', 'imapPort', 'imapSecurity', 'imapUser', 'imapPassword', 'imapMailbox',
  'smtpHost', 'smtpPort', 'smtpSecurity', 'smtpUser', 'smtpPassword',
  'verifyCertificate', 'pollIntervalMs',
]

/** Identity of the exact mail values shown in the form. */
export function mailTestKey(settings = {}) {
  const values = settings || {}
  return JSON.stringify(MAIL_TEST_FIELDS.map((key) => [key, values[key] ?? '']))
}

/**
 * A mail test counts for the exact values shown in the form, or for the saved
 * values behind a running bridge. The second case keeps the rest of setup
 * usable after a GUI/plugin reload, which clears the in-session test result.
 * Editing any mail field changes the key and re-locks setup.
 */
export function mailTestCurrent(settings = {}, status = {}, mailTest = null, appliedMailKey = '') {
  const key = mailTestKey(settings)
  if (mailTest?.ok === true && mailTest?.key === key) return true
  return Boolean(
    status?.configured === true
    && status?.running === true
    && appliedMailKey
    && appliedMailKey === key,
  )
}

/**
 * Derive a guided setup checklist from the values currently in the form and
 * the live bridge status. This is intentionally pure so the GUI can show the
 * same readiness rules that gate the action buttons.
 */
export function setupReadiness(settings = {}, status = {}, extra = {}) {
  const values = settings || {}
  const current = status || {}
  const mode = String(values.remoteMode || current.remoteMode || 'securejoin').toLowerCase() === 'autocrypt'
    ? 'autocrypt'
    : 'securejoin'
  const pinnedContact = String(values.pinnedContact || current.pinnedContact || '').trim().toLowerCase()
  const fingerprint = safeFingerprint(values.pinnedFingerprint || current.pinnedFingerprint)
  const hasAuth = Boolean(values.hasSecureJoinAuth || values.secureJoinAuth || current.secureJoin?.hasAuth)
  const hasImapPassword = Boolean(values.hasImapPassword || values.imapPassword)
  const hasSmtpPassword = Boolean(values.hasSmtpPassword || values.smtpPassword)
  const mailReady = Boolean(
    values.address
    && values.imapHost
    && values.smtpHost
    && hasImapPassword
    && hasSmtpPassword,
  )
  const liveContact = String(current.pinnedContact || '').trim().toLowerCase()
  const liveFingerprint = safeFingerprint(current.pinnedFingerprint)
  const applied = Boolean(current.configured && current.running)
    && liveContact === pinnedContact
    && liveFingerprint === fingerprint
  const secureJoinVerified = Boolean(current.verified)
  const learned = Boolean(current.learnedFingerprint && current.learnedFingerprint === fingerprint)
  const established = Boolean(current.established || learned)
  // SecureJoin has a verified handshake. Autocrypt only establishes that the
  // learned key matches the pin; it must not be described as verified chat.
  const verified = mode === 'autocrypt' ? established && learned : secureJoinVerified

  const steps = [
    {
      id: 'mail',
      label: 'Mail account works',
      done: mailReady && (extra.mailTestOk === true || !extra.mailTestAvailable),
      hint: mailReady
        ? (extra.mailTestOk === true ? 'IMAP and SMTP login verified' : 'Run "Test IMAP + SMTP"')
        : 'Bot address, IMAP/SMTP hosts and passwords are required',
    },
    {
      id: 'pin',
      label: 'Pinned contact and fingerprint',
      done: Boolean(pinnedContact && fingerprint),
      hint: pinnedContact && fingerprint
        ? `${pinnedContact} · ${fingerprint}`
        : 'Paste the invite URL and click "Fill SecureJoin fields", or enter both manually',
    },
  ]
  if (mode === 'securejoin') {
    steps.push({
      id: 'auth',
      label: 'Invite auth code (s=)',
      done: hasAuth,
      hint: hasAuth ? 'Saved locally and hidden' : 'Required; paste the s= value from the contact invite',
    })
  }
  steps.push({
    id: 'apply',
    label: 'Apply settings',
    done: applied,
    hint: applied
      ? 'Bridge is running with these pinned values'
      : 'Click "Save & restart" before starting the handshake',
  })
  steps.push({
    id: 'verify',
    label: mode === 'securejoin' ? 'SecureJoin verified' : 'Autocrypt key confirmed',
    done: verified,
    hint: verified
      ? 'Ready: only this pinned contact can drive OpenCode'
      : (mode === 'securejoin'
        ? 'Start SecureJoin, then wait for the contact to answer'
        : 'Send the Autocrypt request, then wait for a matching reply'),
  })

  const firstPending = steps.find((step) => !step.done)
  const prerequisites = steps.slice(0, -1).every((step) => step.done)
  return {
    mode,
    steps,
    next: firstPending
      ? { id: firstPending.id, label: firstPending.label, hint: firstPending.hint }
      : { id: 'done', label: 'Setup complete', hint: '' },
    mailReady,
    applied,
    verified,
    established,
    secureJoinVerified,
    learned,
    canStartSecureJoin: mode === 'securejoin' && prerequisites && !verified,
    canStartHandshake: mode === 'autocrypt' && prerequisites && !verified,
    // Reset must stay available while changing the pinned contact: stale
    // handshake state from the previous contact can block the new invite.
    canResetContact: applied,
  }
}

/**
 * Human-readable SecureJoin wire progress derived from bridge status events.
 * The GUI uses this to show sent/received steps instead of a silent button.
 */
export function secureJoinProgress(status = {}) {
  const join = status?.secureJoin || {}
  const step = String(join.status || 'idle')
  const reached = {
    request: ['request-sent', 'pubkey-received', 'auth-sent', 'verified'].includes(step),
    pubkey: ['pubkey-received', 'auth-sent', 'verified'].includes(step),
    auth: ['auth-sent', 'verified'].includes(step),
    confirmed: step === 'verified',
  }
  const pending = ['request-sent', 'pubkey-received', 'auth-sent'].includes(step)
  const lines = [
    `- [${reached.request ? 'x' : ' '}] Sent \`vc-request-pubkey\` to ${join.address || status?.pinnedContact || 'the pinned contact'}`,
    `- [${reached.pubkey ? 'x' : ' '}] Received signed \`vc-pubkey\` with the pinned fingerprint`,
    `- [${reached.auth ? 'x' : ' '}] Sent encrypted \`vc-request-with-auth\``,
    `- [${reached.confirmed ? 'x' : ' '}] Received \`vc-contact-confirm\` — verified`,
  ]
  if (step === 'error') lines.push('', `**Failed:** ${status?.lastError || 'SecureJoin error'}`)
  if (step === 'cancelled') lines.push('', 'Cancelled. Nothing else will be accepted until you start again.')
  if (pending) lines.push('', 'Waiting for the contact. Keep both mail clients open; greylisting can delay a reply.')
  return {
    step,
    pending,
    failed: step === 'error',
    cancelled: step === 'cancelled',
    verified: step === 'verified',
    lines,
    markdown: lines.join('\n'),
  }
}

export function setupMarkdown(readiness) {
  const value = readiness || setupReadiness()
  const lines = [
    `**Next:** ${value.next.label}${value.next.hint ? ` — ${value.next.hint}` : ''}`,
    '',
    ...value.steps.map((step) => (
      `- [${step.done ? 'x' : ' '}] **${step.label}**${step.hint ? ` — ${step.hint}` : ''}`
    )),
  ]
  return lines.join('\n')
}
