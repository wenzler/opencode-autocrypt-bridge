function foldKeydata(prefix, publicB64, lineWidth = 76) {
  const chunks = String(publicB64).match(new RegExp(`.{1,${lineWidth}}`, 'g')) || []
  return `${prefix}${chunks.join('\r\n ')}`
}

/** Build an Autocrypt header value. keydata must be the last attribute. */
export function autocryptHeader(address, publicB64, preferEncryptMutual, lineWidth = 76) {
  const prefix = `addr=${address}; ${preferEncryptMutual ? 'prefer-encrypt=mutual; ' : ''}keydata=`
  return foldKeydata(prefix, publicB64, lineWidth)
}

/** Build an Autocrypt-Gossip header value (no prefer-encrypt attribute). */
export function autocryptGossipHeader(address, publicB64, lineWidth = 76) {
  return foldKeydata(`addr=${address}; keydata=`, publicB64, lineWidth)
}

/** Unfold a header value that was continued on lines starting with whitespace. */
export function unfold(value) {
  return String(value || '').replace(/\r?\n[ \t]+/g, '')
}

export function normalizeBase64(value) {
  return String(value || '').replace(/\s+/g, '')
}

/**
 * Normalize an OpenPGP fingerprint. Accepts bare hex, grouped hex,
 * `OPENPGP4FPR:` URIs, and contact-invite URIs whose fragment starts with the
 * fingerprint. Only the fingerprint is used; all other URI parameters are
 * ignored by this function.
 */
export function normalizeFingerprint(value) {
  const text = String(value || '').trim()
  if (!text) return ''
  const decoded = text.replace(/%23/gi, '#')
  const openpgp = /^OPENPGP4FPR:\s*([^#&]+)/i.exec(decoded)
  let token
  if (openpgp) {
    token = openpgp[1]
  } else {
    const hash = decoded.indexOf('#')
    token = (hash >= 0 ? decoded.slice(hash + 1) : decoded).split('&')[0]
  }
  const hex = token.replace(/[^0-9a-f]/gi, '').toUpperCase()
  if (!/^(?:[0-9A-F]{40}|[0-9A-F]{64})$/.test(hex)) {
    throw new Error('Invalid OpenPGP fingerprint: expected 40 or 64 hex characters')
  }
  return hex
}

/**
 * Parse a contact invite URI for convenience only.
 *
 * Many OpenPGP clients export a URI such as `OPENPGP4FPR:FPR#...` or
 * `https://example.org/#FPR&...&a=user%40example.org`. This reads only the
 * fingerprint, address, display name and version locally. Invite-number/auth
 * code parameters are intentionally not returned; nothing is fetched.
 */
export function parseInviteUrl(value) {
  const text = String(value || '').trim()
  if (!text) return undefined
  const decoded = text.replace(/%23/gi, '#')
  const openpgp = /^OPENPGP4FPR:\s*([^#&]+)(?:#([\s\S]*))?$/i.exec(decoded)
  let fragment
  if (openpgp) {
    fragment = openpgp[1] + (openpgp[2] ? `&${openpgp[2]}` : '')
  } else {
    const hash = decoded.indexOf('#')
    fragment = hash >= 0 ? decoded.slice(hash + 1) : decoded.replace(/^https?:\/\/[^/]+\/?/i, '')
  }
  const [rawFingerprint, ...pairs] = fragment.split('&')
  const fingerprint = normalizeFingerprint(rawFingerprint)
  const params = new URLSearchParams(pairs.join('&'))
  return {
    fingerprint,
    address: String(params.get('a') || '').toLowerCase(),
    name: String(params.get('n') || ''),
    version: String(params.get('v') || ''),
  }
}

/**
 * Remove invite-number/auth-code parameters from a contact invite URL.
 *
 * Invite-number/auth-code parameters are never used or stored by this bridge.
 * RPC and GUI displays see this redacted form, which keeps only the public
 * fields used for local pin prefill.
 */
export function redactInviteUrl(value) {
  const text = String(value || '').trim()
  if (!text) return ''
  const withoutSecretPairs = (part) => part
    .split('&')
    .filter((pair) => !/^(?:i|j|s)=/i.test(pair))
    .join('&')

  const hash = text.indexOf('#')
  if (hash >= 0) {
    const prefix = text.slice(0, hash + 1)
    const [fingerprint, ...pairs] = text.slice(hash + 1).split('&')
    const kept = withoutSecretPairs(pairs.join('&'))
    return `${prefix}${fingerprint}${kept ? `&${kept}` : ''}`
  }
  const openpgp = /^(OPENPGP4FPR:\s*)([\s\S]+)$/i.exec(text)
  if (openpgp) {
    const [fingerprint, ...pairs] = openpgp[2].split('&')
    const kept = withoutSecretPairs(pairs.join('&'))
    return `${openpgp[1]}${fingerprint}${kept ? `&${kept}` : ''}`
  }
  return text
}

/** Remove armor framing and return the binary Transferable Public Key as base64. */
export function armorToBase64(armored) {
  const lines = String(armored).split(/\r?\n/)
  const start = lines.findIndex((line) => line.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----'))
  const end = lines.findIndex((line, index) => index > start && line.startsWith('-----END PGP PUBLIC KEY BLOCK-----'))
  if (start < 0 || end <= start) throw new Error('Invalid armored public key')
  const data = lines
    .slice(start + 1, end)
    .map((line) => line.trim())
    .filter((line) => line && !line.includes(':') && /^[A-Za-z0-9+/=]+$/.test(line))
    .join('')
  if (!data) throw new Error('Empty armored public key')
  return data
}

/** Convert an armored public key, or already-base64 keydata, to Autocrypt keydata. */
export function publicKeyToBase64(value) {
  const text = String(value || '').trim()
  if (!text) return ''
  if (!text.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) return normalizeBase64(text)
  return armorToBase64(text)
}

/** Parse an Autocrypt header and return { addr, keydata, preferEncrypt }. */
export function parseAutocryptHeader(rawValue, from) {
  const value = unfold(rawValue)
  const attributes = new Map()
  for (const part of value.split(';')) {
    const index = part.indexOf('=')
    if (index < 0) continue
    const key = part.slice(0, index).trim().toLowerCase()
    const val = part.slice(index + 1).trim().replace(/^"(.*)"$/, '$1')
    attributes.set(key, val)
  }
  const addr = String(attributes.get('addr') || '').trim().toLowerCase()
  if (!addr || addr !== String(from || '').trim().toLowerCase()) return undefined
  const keydata = normalizeBase64(attributes.get('keydata'))
  if (!keydata) return undefined
  return { addr, keydata, preferEncrypt: attributes.get('prefer-encrypt') === 'mutual' }
}
