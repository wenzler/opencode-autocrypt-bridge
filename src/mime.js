import { randomUUID } from 'node:crypto'
import { autocryptHeader } from './headers.js'

const CRLF = '\r\n'

export function encodeHeader(value) {
  const text = String(value || '')
  if (/^[\x20-\x7e]*$/.test(text)) return text
  return `=?UTF-8?B?${Buffer.from(text, 'utf8').toString('base64')}?=`
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
  if (declared && !/^application\/octet-stream$/i.test(declared)) return declared.split(';')[0].toLowerCase()
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
  return [
    `Content-Type: ${contentType}; charset=utf-8; name="${filename}"${CRLF}`,
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
    ...extraHeaders.filter(Boolean),
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

/** Build an RFC 8098 read receipt shaped like Delta Chat's MDN. */
export function buildReadReceiptMime({ originalMessageID }) {
  const boundary = `opencode-mdn-${randomUUID()}`
  const original = String(originalMessageID || '').trim().replace(/^<|>$/g, '').replace(/[\r\n]/g, '')
  const body = [
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    'This is a receipt notification.',
    `--${boundary}`,
    'Content-Type: message/disposition-notification',
    '',
    `Original-Message-ID: <${original}>`,
    'Disposition: manual-action/MDN-sent-automatically; displayed',
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
  const name = String(cfg.displayName || '').replace(/"/g, '')
  const fromName = /^[\x20-\x7e]*$/.test(name) ? `"${name}"` : encodeHeader(name)
  const headerLines = [
    `From: ${from || `${fromName} <${cfg.address}>`}`,
    `To: <${to}>`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${messageId}>`,
    ...(inReplyTo ? [`In-Reply-To: ${inReplyTo}`, `References: ${inReplyTo}`] : []),
    ...(publicB64
      ? [`Autocrypt: ${autocryptHeader(autocryptAddress || cfg.address, publicB64, cfg.key.preferEncryptMutual)}`]
      : []),
    // Display-compatibility marker only. It is not a handshake signal and
    // never enables invite-protocol behavior.
    'Chat-Version: 1.0',
    'X-OpenCode-Autocrypt-Bridge: 1',
    ...headers,
    'MIME-Version: 1.0',
    `Content-Type: ${contentType}`,
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
    const fields = parseRawHeaders(chunk.slice(partSeparator + 2))
    const disposition = String(fields.get('disposition') || '')
    if (!disposition) continue
    return {
      disposition,
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
