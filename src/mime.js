import { randomUUID } from 'node:crypto'
import { autocryptHeader } from './headers.js'

const CRLF = '\r\n'

export function encodeHeader(value) {
  const text = String(value || '')
  if (/^[\x20-\x7e]*$/.test(text)) return text
  return `=?UTF-8?B?${Buffer.from(text, 'utf8').toString('base64')}?=`
}

/** Flatten a value so it can never introduce a new RFC 5322 header line. */
export function safeHeaderValue(value, maxLength = 512) {
  return String(value ?? '')
    .replace(/[\r\n\x00-\x1f\x7f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength)
}

/** Validate an extra header line; return '' for anything malformed. */
export function safeHeaderLine(value) {
  const text = String(value ?? '').replace(/[\r\n\x00-\x1f\x7f]/g, ' ')
  const colon = text.indexOf(':')
  if (colon <= 0 || !/^[!-9;-~]+$/.test(text.slice(0, colon))) return ''
  return text
}

/** Normalize a Message-ID for use inside angle brackets in a header. */
export function headerMessageId(value) {
  const id = safeHeaderValue(value, 512).replace(/[<>]/g, '')
  return id ? `<${id}>` : ''
}

function base64Lines(buffer) {
  const encoded = Buffer.from(buffer).toString('base64')
  return (encoded.match(/.{1,76}/g) || []).join(CRLF)
}

export function safeFilename(name) {
  const base = String(name || 'attachment')
    .split(/[\\/]/)
    .pop()
    .replace(/[\x00-\x1f\x7f"]/g, '')
    .trim()
  return (base || 'attachment').slice(0, 180)
}

export function contentTypeOf(filename, declared) {
  const candidate = String(declared || '').split(';')[0].trim()
  if (candidate && !/^application\/octet-stream$/i.test(candidate)
      && /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/.test(candidate)) {
    return candidate.toLowerCase()
  }
  const ext = String(filename).toLowerCase().split('.').pop()
  const types = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp',
    html: 'text/html', htm: 'text/html', txt: 'text/plain', md: 'text/markdown',
    pdf: 'application/pdf', json: 'application/json',
  }
  return types[ext] || 'application/octet-stream'
}

function textPart(text) {
  return [
    `Content-Type: text/plain; charset=utf-8${CRLF}`,
    `Content-Transfer-Encoding: base64${CRLF}`,
    CRLF,
    base64Lines(Buffer.from(text || '', 'utf8')),
  ].join('')
}

function attachmentPart(attachment) {
  const filename = safeFilename(attachment.filename)
  const contentType = contentTypeOf(filename, attachment.contentType)
  // A charset parameter is only meaningful for text/* parts. Sending it on
  // image/pdf parts makes some mail clients refuse to render the attachment.
  const charset = contentType.startsWith('text/') ? '; charset=utf-8' : ''
  return [
    `Content-Type: ${contentType}${charset}; name="${filename}"${CRLF}`,
    `Content-Disposition: attachment; filename="${filename}"${CRLF}`,
    `Content-Transfer-Encoding: base64${CRLF}`,
    CRLF,
    base64Lines(attachment.content),
  ].join('')
}

/** Build the inner MIME entity that is sent in the clear or encrypted as PGP/MIME. */
export function buildInnerMime({ text, attachments = [], headers: extraHeaders = [] }) {
  const boundary = `opencode-${randomUUID()}`
  const parts = [textPart(text), ...attachments.map(attachmentPart)]
  const body = parts.map((part) => `--${boundary}${CRLF}${part}${CRLF}`).join('') + `--${boundary}--${CRLF}`
  const contentType = `multipart/mixed; boundary="${boundary}"`
  const headers = [
    ...extraHeaders.map(safeHeaderLine).filter(Boolean),
    `MIME-Version: 1.0`,
    `Content-Type: ${contentType}`,
    '',
    '',
  ].join(CRLF)
  return {
    contentType,
    body: Buffer.from(body, 'utf8'),
    entity: Buffer.concat([Buffer.from(headers, 'utf8'), Buffer.from(body, 'utf8')]),
  }
}

/**
 * Build an RFC 8098 MDN that also satisfies Delta Chat's read-receipt format.
 * RFC 8098 requires Final-Recipient and recommends Reporting-UA; Delta Chat
 * requires the displayed disposition and the exact Original-Message-ID.
 */
export function buildReadReceiptMime({ originalMessageID, recipient = '' }) {
  const boundary = `opencode-mdn-${randomUUID()}`
  const original = String(originalMessageID || '').trim().replace(/^<|>$/g, '').replace(/[\r\n]/g, '')
  // RFC 8098 Final-Recipient is the original recipient, not the MDN destination.
  const finalRecipient = String(recipient || '').trim().replace(/[\r\n]/g, '')
  const fields = [
    'Reporting-UA: opencode-autocrypt-bridge',
    ...(finalRecipient ? [`Final-Recipient: rfc822; ${finalRecipient}`] : []),
    `Original-Message-ID: <${original}>`,
    'Disposition: manual-action/MDN-sent-automatically; displayed',
  ].join(CRLF)
  const body = [
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    'This is a receipt notification.',
    `--${boundary}`,
    'Content-Type: message/disposition-notification',
    'Content-Transfer-Encoding: 7bit',
    '',
    fields,
    '',
    `--${boundary}--`,
    '',
  ].join(CRLF)
  const contentType = `multipart/report; report-type=disposition-notification; boundary="${boundary}"`
  const headers = `MIME-Version: 1.0${CRLF}Content-Type: ${contentType}${CRLF}${CRLF}`
  return {
    contentType,
    body: Buffer.from(body, 'utf8'),
    entity: Buffer.concat([Buffer.from(headers, 'utf8'), Buffer.from(body, 'utf8')]),
  }
}

export function buildPgpMime(armored) {
  const boundary = `opencode-encrypted-${randomUUID()}`
  const body = [
    `--${boundary}${CRLF}`,
    `Content-Type: application/pgp-encrypted${CRLF}`,
    CRLF,
    `Version: 1${CRLF}`,
    CRLF,
    `--${boundary}${CRLF}`,
    `Content-Type: application/octet-stream${CRLF}`,
    `Content-Transfer-Encoding: 7bit${CRLF}`,
    CRLF,
    String(armored).trim(),
    CRLF,
    `--${boundary}--${CRLF}`,
  ].join('')
  return {
    contentType: `multipart/encrypted; protocol="application/pgp-encrypted"; boundary="${boundary}"`,
    body: Buffer.from(body, 'utf8'),
  }
}

export function buildMail({
  cfg,
  to,
  subject,
  inReplyTo,
  messageId,
  publicB64,
  contentType,
  body,
  headers = [],
  from,
  autocryptAddress,
}) {
  const name = safeHeaderValue(cfg.displayName, 120).replace(/"/g, '')
  const fromName = /^[\x20-\x7e]*$/.test(name) ? `"${name}"` : encodeHeader(name)
  const fromAddress = safeHeaderValue(from || `${fromName} <${safeHeaderValue(cfg.address, 320)}>`, 320)
  const toAddress = safeHeaderValue(to, 320)
  const replyId = headerMessageId(inReplyTo)
  const headerLines = [
    `From: ${fromAddress}`,
    `To: <${toAddress}>`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: ${headerMessageId(messageId)}`,
    ...(replyId ? [`In-Reply-To: ${replyId}`, `References: ${replyId}`] : []),
    ...(publicB64
      ? [`Autocrypt: ${autocryptHeader(autocryptAddress || cfg.address, publicB64, cfg.key.preferEncryptMutual)}`]
      : []),
    // Display-compatibility marker only. It is not a handshake signal and
    // never enables invite-protocol behavior.
    'Chat-Version: 1.0',
    'X-OpenCode-Autocrypt-Bridge: 1',
    ...headers.map(safeHeaderLine).filter(Boolean),
    'MIME-Version: 1.0',
    `Content-Type: ${safeHeaderValue(contentType)}`,
    '',
    '',
  ].join(CRLF)
  return Buffer.concat([Buffer.from(headerLines, 'utf8'), Buffer.from(body)])
}

export function parseRawHeaders(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString('latin1') : String(raw)
  const separator = text.indexOf('\r\n\r\n')
  const lfSeparator = text.indexOf('\n\n')
  const end = separator >= 0 ? separator : (lfSeparator >= 0 ? lfSeparator : text.length)
  const headerText = text.slice(0, end)
  const headers = new Map()
  let current
  for (const line of headerText.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && current) {
      headers.set(current, `${headers.get(current) || ''} ${line.trim()}`)
      continue
    }
    const colon = line.indexOf(':')
    if (colon <= 0) continue
    current = line.slice(0, colon).trim().toLowerCase()
    headers.set(current, line.slice(colon + 1).trim())
  }
  return headers
}

/** Return every unfolded value of one header, preserving repeated headers. */
export function headerValues(raw, name) {
  const text = Buffer.isBuffer(raw) ? raw.toString('latin1') : String(raw)
  const separator = text.indexOf('\r\n\r\n')
  const lfSeparator = text.indexOf('\n\n')
  const end = separator >= 0 ? separator : (lfSeparator >= 0 ? lfSeparator : text.length)
  const wanted = String(name).toLowerCase()
  const values = []
  let current = ''
  for (const line of text.slice(0, end).split(/\r?\n/)) {
    if (/^[ \t]/.test(line)) {
      if (current) values[values.length - 1] += line.trim()
      continue
    }
    const colon = line.indexOf(':')
    if (colon <= 0) {
      current = ''
      continue
    }
    const key = line.slice(0, colon).trim().toLowerCase()
    current = key === wanted ? line.slice(colon + 1).trim() : ''
    if (current) values.push(current)
  }
  return values
}

function decodeTransferEncoding(value, encoding) {
  const text = String(value || '')
  if (/^\s*base64\s*$/i.test(encoding)) {
    return Buffer.from(text.replace(/\s+/g, ''), 'base64').toString('latin1')
  }
  if (/^\s*quoted-printable\s*$/i.test(encoding)) {
    return text
      .replace(/=\r?\n/g, '')
      .replace(/=([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
  }
  return text
}

/** Read the machine-readable part of an MDN, including Delta Chat's variant. */
export function parseDispositionNotification(raw) {
  const text = (Buffer.isBuffer(raw) ? raw.toString('latin1') : String(raw || '')).replace(/\r\n/g, '\n')
  const separator = text.indexOf('\n\n')
  if (separator < 0) return undefined
  const headers = parseRawHeaders(text.slice(0, separator))
  const contentType = String(headers.get('content-type') || '')
  if (!/^multipart\/report/i.test(contentType)) return undefined
  if (!/report-type\s*=\s*"?disposition-notification"?/i.test(contentType)) return undefined
  const boundary = /(?:^|;)\s*boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i.exec(contentType)
  if (!boundary) return undefined
  const marker = `--${boundary[1] || boundary[2]}`
  const body = text.slice(separator + 2)
  for (const chunk of body.split(marker).slice(1)) {
    if (chunk.startsWith('--')) break
    const partSeparator = chunk.indexOf('\n\n')
    if (partSeparator < 0) continue
    const partHeaders = parseRawHeaders(chunk.slice(0, partSeparator))
    if (!/^message\/disposition-notification/i.test(String(partHeaders.get('content-type') || ''))) continue
    const fields = parseRawHeaders(decodeTransferEncoding(
      chunk.slice(partSeparator + 2),
      String(partHeaders.get('content-transfer-encoding') || ''),
    ))
    const disposition = String(fields.get('disposition') || '')
    if (!disposition) continue
    const action = String(fields.get('action') || disposition.split(';').slice(1).join(';') || '')
      .trim()
      .toLowerCase()
    return {
      disposition,
      action,
      originalMessageID: String(fields.get('original-message-id') || headers.get('in-reply-to') || ''),
    }
  }
  return undefined
}

export function extractArmored(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw)
  const match = /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/.exec(text)
  return match ? match[0] : undefined
}

export function isEncrypted(headers) {
  const contentType = String(headers.get('content-type') || '').toLowerCase()
  return contentType.includes('multipart/encrypted') && contentType.includes('pgp-encrypted')
}
