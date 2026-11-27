import { normalizeFingerprint } from './headers.js'

function safeFingerprint(value) {
  try {
    return normalizeFingerprint(value)
  } catch {
    return ''
  }
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
  const verified = Boolean(current.verified)
  const learned = Boolean(current.learnedFingerprint && current.learnedFingerprint === fingerprint)

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
    learned,
    canStartSecureJoin: mode === 'securejoin' && prerequisites && !verified,
    canStartHandshake: mode === 'autocrypt' && prerequisites && !verified,
    // Reset must stay available while changing the pinned contact: stale
    // handshake state from the previous contact can block the new invite.
    canResetContact: applied,
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
