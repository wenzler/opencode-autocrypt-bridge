import { parseInviteUrl, redactInviteUrl } from './headers.js'
import { normalizeHost } from './values.js'

/**
 * Single registry for settings shown in the Desktop GUI, accepted by RPC and
 * loaded by the bridge. Adding a field here makes it available everywhere;
 * transport-only environment settings stay in config.js.
 */
const spec = (type, fallback = '', extra = {}) => ({ type, fallback, ...extra })

export const SETTING_SPECS = {
  address: spec('string'),
  displayName: spec('string'),
  imapHost: spec('string'),
  imapPort: spec('number', 993),
  imapSecurity: spec('string', 'tls', { enum: ['tls', 'starttls', 'plain'] }),
  imapUser: spec('string'),
  imapPassword: spec('string'),
  imapMailbox: spec('string', 'INBOX'),
  smtpHost: spec('string'),
  smtpPort: spec('number', 465),
  smtpSecurity: spec('string', 'tls', { enum: ['tls', 'starttls', 'plain'] }),
  smtpUser: spec('string'),
  smtpPassword: spec('string'),
  pinnedContact: spec('string'),
  pinnedFingerprint: spec('string'),
  pinnedContactKey: spec('string'),
  inviteUrl: spec('string'),
  remoteMode: spec('string', 'securejoin', { enum: ['securejoin', 'autocrypt'] }),
  secureJoinAuth: spec('string'),
  secureJoinName: spec('string'),
  secureJoinVersion: spec('string', '3'),
  secureJoinRelays: spec('string'),
  secureJoinInviteNumber: spec('string'),
  requireEncrypted: spec('boolean', false),
  pollIntervalMs: spec('number', 30_000),
  verifyCertificate: spec('boolean', true),
  deleteAfterRead: spec('boolean', false),
  privateKeyArmored: spec('string'),
  keyPassphrase: spec('string'),
  generateKey: spec('boolean', true),
  preferEncryptMutual: spec('boolean', true),
  emailDecisions: spec('boolean', true),
  emailHighRiskDecisions: spec('boolean', false),
  emailQuestions: spec('boolean', true),
  emailPeek: spec('boolean', true),
  emailTail: spec('boolean', true),
  emailSendFiles: spec('boolean', true),
  emailWatch: spec('boolean', true),
  emailReadReceipts: spec('boolean', true),
  emailProgress: spec('boolean', true),
  emailProgressIntervalMs: spec('number', 20_000),
}

export const SETTING_KEYS = Object.keys(SETTING_SPECS)

export const SECRET_KEYS = new Set([
  'imapPassword', 'smtpPassword', 'privateKeyArmored', 'keyPassphrase', 'secureJoinAuth',
])

export const HOST_KEYS = new Set(['imapHost', 'smtpHost'])

export const UI_DEFAULTS = Object.fromEntries(
  Object.entries(SETTING_SPECS)
    .filter(([, value]) => value.fallback !== '')
    .map(([key, value]) => [key, value.fallback]),
)

/** JSON-schema properties accepted by settings RPC inputs. */
export const SETTINGS_INPUT_PROPERTIES = Object.fromEntries(
  Object.entries(SETTING_SPECS).map(([key, value]) => [
    key,
    { type: value.type, ...(value.enum ? { enum: value.enum } : {}) },
  ]),
)

/** JSON-schema properties for the getSettings RPC result. */
export const SETTINGS_OUTPUT_PROPERTIES = {
  ...SETTINGS_INPUT_PROPERTIES,
  hasImapPassword: { type: 'boolean' },
  hasSmtpPassword: { type: 'boolean' },
  hasPinnedContactKey: { type: 'boolean' },
  hasSecureJoinAuth: { type: 'boolean' },
  hasPrivateKey: { type: 'boolean' },
  hasKeyPassphrase: { type: 'boolean' },
}

export function storedSettings(stored) {
  const result = {}
  if (!stored || typeof stored !== 'object') return result
  for (const key of SETTING_KEYS) {
    if (stored[key] === undefined || stored[key] === null || stored[key] === '') continue
    result[key] = stored[key]
  }
  return result
}

/** Build the GUI/RPC view from raw flat settings, including redacted secrets. */
export function settingsView(values = {}) {
  const view = {}
  for (const key of SETTING_KEYS) view[key] = values[key] ?? ''
  for (const [key, fallback] of Object.entries(UI_DEFAULTS)) {
    if (values[key] === undefined || values[key] === null || values[key] === '') view[key] = fallback
  }
  view.hasImapPassword = Boolean(values.imapPassword)
  view.hasSmtpPassword = Boolean(values.smtpPassword)
  view.hasPinnedContactKey = Boolean(values.pinnedContactKey)
  view.hasPrivateKey = Boolean(values.privateKeyArmored)
  view.hasKeyPassphrase = Boolean(values.keyPassphrase)
  let inviteAuth = ''
  try {
    inviteAuth = parseInviteUrl(values.inviteUrl)?.auth || ''
  } catch {}
  view.hasSecureJoinAuth = Boolean(values.secureJoinAuth || inviteAuth)
  for (const key of SECRET_KEYS) view[key] = ''
  // The full invite URL is kept locally because s= is the handshake auth code.
  // Only this displayed copy is redacted.
  view.inviteUrl = redactInviteUrl(view.inviteUrl)
  return view
}

function hasInviteSecret(url) {
  const text = String(url || '')
  const fragment = text.includes('#') ? text.slice(text.indexOf('#') + 1) : text
  return /(?:^|&)(?:s|i|j)=/i.test(fragment)
}

/**
 * Apply a GUI/RPC settings form to stored values. Blank secret fields keep the
 * saved secret; a redacted invite URL shown by getSettings also keeps it. A
 * pasted URL with new s=/i=/j= values always replaces the stored invite.
 */
export function applySettingValues(stored = {}, input = {}) {
  const values = { ...stored }
  const previousInvite = String(stored.inviteUrl || '')
  const previousRedacted = redactInviteUrl(previousInvite)
  for (const key of SETTING_KEYS) {
    const value = input[key]
    if (value === undefined || value === null) continue
    if (SECRET_KEYS.has(key) && value === '') continue
    if (key === 'inviteUrl') {
      const incoming = String(value).trim()
      if (previousInvite && incoming === previousRedacted && !hasInviteSecret(incoming)) continue
    }
    let storedValue = value
    if (HOST_KEYS.has(key)) storedValue = normalizeHost(value)
    if (storedValue === '') delete values[key]
    else values[key] = storedValue
  }
  return values
}
