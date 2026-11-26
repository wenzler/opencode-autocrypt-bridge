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
export function buildInnerMime({ text, attachments = [] }) {
  const boundary = `opencode-${randomUUID()}`
  const parts = [textPart(text), ...attachments.map(attachmentPart)]
  const body = parts.map((part) => `--${boundary}${CRLF}${part}${CRLF}`).join('') + `--${boundary}--${CRLF}`
  const contentType = `multipart/mixed; boundary="${boundary}"`
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
}) {
  const name = String(cfg.displayName || '').replace(/"/g, '')
  const fromName = /^[\x20-\x7e]*$/.test(name) ? `"${name}"` : encodeHeader(name)
  const headerLines = [
    `From: ${fromName} <${cfg.address}>`,
    `To: <${to}>`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${messageId}>`,
    ...(inReplyTo ? [`In-Reply-To: ${inReplyTo}`, `References: ${inReplyTo}`] : []),
    ...(publicB64
      ? [`Autocrypt: ${autocryptHeader(cfg.address, publicB64, cfg.key.preferEncryptMutual)}`]
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
  const headerText = separator >= 0 ? text.slice(0, separator) : text.slice(0, text.indexOf('\n\n'))
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

export function extractArmored(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw)
  const match = /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/.exec(text)
  return match ? match[0] : undefined
}

export function isEncrypted(headers) {
  const contentType = String(headers.get('content-type') || '').toLowerCase()
  return contentType.includes('multipart/encrypted') && contentType.includes('pgp-encrypted')
}
