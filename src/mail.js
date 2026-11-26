import { createHash } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { isIP } from 'node:net'
import { ImapFlow } from 'imapflow'
import { simpleParser } from 'mailparser'
import nodemailer from 'nodemailer'
import { decryptMessage, keyFingerprint } from './crypto.js'
import { parseAutocryptHeader } from './headers.js'
import { extractArmored, isEncrypted, parseDispositionNotification, parseRawHeaders, safeFilename } from './mime.js'

const ALLOWED_ATTACHMENT_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'text/html', 'text/plain', 'text/markdown', 'application/pdf',
])

export function sleep(ms, signal) {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve()
    const done = () => { clearTimeout(timer); signal.removeEventListener('abort', done); resolve() }
    const timer = setTimeout(done, ms)
    signal.addEventListener('abort', done, { once: true })
  })
}

export function fromAddress(raw) {
  const match = /(?:^|\n)from:[^\n]*?<([^<>\s@]+@[^<>\s>]+)>/i.exec(raw) || /(?:^|\n)from:\s*([^<>\s@]+@[^<>\s>]+)/i.exec(raw)
  return match ? match[1].toLowerCase() : undefined
}

/** Adapted from opencode-email-sync src/mail/imap.ts (MIT). */
export function imapOptions(cfg, password) {
  const imap = cfg.imap
  return {
    host: imap.host,
    port: imap.port,
    secure: imap.security === 'tls',
    doSTARTTLS: imap.security === 'starttls',
    auth: { user: imap.user, pass: password },
    logger: false,
    tls: {
      servername: isIP(imap.host) ? undefined : imap.host,
      rejectUnauthorized: imap.verifyCertificate,
    },
    disableAutoIdle: true,
    socketTimeout: Math.max(60_000, imap.pollIntervalMs * 2),
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    maxLiteralSize: cfg.maxMessageBytes,
    maxResponseSize: cfg.maxMessageBytes + 65_536,
    maxLineLength: 65_536,
  }
}

const checkpointKey = (mailbox) => `imap:${mailbox}`

function checkpointStart(store, mailbox, validity, uidNext) {
  const raw = store.get(checkpointKey(mailbox))
  if (!raw) {
    store.set(checkpointKey(mailbox), { validity, uid: uidNext - 1 })
    return uidNext
  }
  if (raw.validity !== validity) {
    store.set(checkpointKey(mailbox), { validity, uid: 0 })
    return 1
  }
  return raw.uid + 1
}

/** Ported from opencode-email-sync: IDLE with a periodic reconciliation wake-up. */
export async function startImap(cfg, store, onMessage, signal, log) {
  let failures = 0
  while (!signal.aborted) {
    const client = new ImapFlow(imapOptions(cfg, cfg.imap.password))
    client.on('error', () => log('IMAP connection error; reconnecting'))
    client.on('exists', () => { if (client.idling) void client.noop().catch(() => {}) })
    const abort = () => client.close()
    signal.addEventListener('abort', abort, { once: true })
    try {
      await client.connect()
      await client.mailboxOpen(cfg.imap.mailbox)
      failures = 0
      while (!signal.aborted && client.usable) {
        const mailbox = client.mailbox
        if (!mailbox) throw new Error('IMAP mailbox unavailable')
        const validity = String(mailbox.uidValidity)
        const start = checkpointStart(store, cfg.imap.mailbox, validity, mailbox.uidNext)
        if (mailbox.exists > 0) {
          const metadata = []
          for await (const message of client.fetch(`${start}:*`, { uid: true, size: true }, { uid: true })) {
            if (message.uid >= start) metadata.push({ uid: message.uid, size: message.size ?? Infinity })
          }
          metadata.sort((a, b) => a.uid - b.uid)
          for (const message of metadata) {
            if (signal.aborted) break
            const key = checkpointKey(cfg.imap.mailbox)
            if (message.size > cfg.maxMessageBytes) {
              store.set(key, { validity, uid: message.uid })
              continue
            }
            const fetched = await client.fetchOne(message.uid, { source: true }, { uid: true })
            if (fetched?.source) {
              try {
                await onMessage(fetched.source)
                store.set(key, { validity, uid: message.uid })
              } catch (error) {
                log(`Failed to handle message UID ${message.uid}: ${error.message}`)
              }
            }
          }
        }
        if (client.capabilities.has('IDLE')) {
          const idle = client.idle()
          const wake = new AbortController()
          const stopWake = () => wake.abort()
          signal.addEventListener('abort', stopWake, { once: true })
          try {
            await Promise.race([idle, sleep(cfg.imap.pollIntervalMs, wake.signal)])
            if (!signal.aborted && client.usable) await client.noop()
            await idle
          } finally {
            wake.abort()
            signal.removeEventListener('abort', stopWake)
          }
        } else {
          await sleep(cfg.imap.pollIntervalMs, signal)
          if (!signal.aborted) await client.noop()
        }
      }
    } catch (error) {
      if (!signal.aborted) log(`IMAP loop error: ${error.message}`)
    } finally {
      signal.removeEventListener('abort', abort)
      client.close()
    }
    if (!signal.aborted) {
      await sleep(Math.min(60_000, 1_000 * 2 ** Math.min(failures++, 6)), signal)
    }
  }
  log('IMAP loop stopped')
}

/** Re-read messages already in the mailbox without rewinding the live IDLE loop. */
export async function rescanMailbox(cfg, store, onMessage, log, signal = new AbortController().signal) {
  const client = new ImapFlow(imapOptions(cfg, cfg.imap.password))
  const abort = () => client.close()
  signal.addEventListener('abort', abort, { once: true })
  try {
    await client.connect()
    await client.mailboxOpen(cfg.imap.mailbox)
    const mailbox = client.mailbox
    if (!mailbox) throw new Error('IMAP mailbox unavailable')
    const validity = String(mailbox.uidValidity)
    const checkpoint = checkpointKey(cfg.imap.mailbox)
    const metadata = []
    for await (const message of client.fetch('1:*', { uid: true, size: true }, { uid: true })) {
      if (signal.aborted) break
      if (message.uid) metadata.push({ uid: message.uid, size: message.size ?? Infinity })
    }
    metadata.sort((a, b) => a.uid - b.uid)
    let processed = 0
    for (const message of metadata) {
      if (signal.aborted) break
      if (message.size > cfg.maxMessageBytes) {
        log(`Rescan skipped oversized message UID ${message.uid}`)
        continue
      }
      const fetched = await client.fetchOne(message.uid, { source: true }, { uid: true })
      if (!fetched?.source) continue
      try {
        await onMessage(fetched.source)
        const current = store.get(checkpoint)
        const previousUid = current && current.validity === validity ? Number(current.uid) || 0 : 0
        store.set(checkpoint, { validity, uid: Math.max(previousUid, message.uid) })
        processed += 1
      } catch (error) {
        log(`Rescan failed to handle message UID ${message.uid}: ${error.message}`)
      }
    }
    return { processed, total: metadata.length }
  } finally {
    signal.removeEventListener('abort', abort)
    client.close()
  }
}

/** Adapted from opencode-email-sync src/mail/smtp.ts (MIT). */
export function createSender(cfg) {
  const smtp = cfg.smtp
  const options = {
    host: smtp.host,
    port: smtp.port,
    secure: smtp.security === 'tls',
    requireTLS: smtp.security === 'starttls',
    ignoreTLS: smtp.security === 'plain',
    auth: { user: smtp.user, pass: smtp.password },
    tls: {
      servername: isIP(smtp.host) ? undefined : smtp.host,
      rejectUnauthorized: smtp.verifyCertificate,
    },
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
  }
  return {
    async send(raw, to) {
      const transport = nodemailer.createTransport(options)
      try {
        await transport.sendMail({ envelope: { from: cfg.address, to: [to] }, raw })
      } finally {
        transport.close()
      }
    },
  }
}

async function saveAttachments(cfg, parsed, messageId, log) {
  const saved = []
  if (!parsed.attachments?.length) return saved
  await mkdir(cfg.attachmentDir, { recursive: true })
  const hash = createHash('sha256').update(messageId || String(Date.now())).digest('hex').slice(0, 12)
  for (const attachment of parsed.attachments) {
    const filename = safeFilename(attachment.filename || attachment.contentId || 'attachment')
    const contentType = String(attachment.contentType || '').split(';')[0].toLowerCase()
    const size = attachment.content?.byteLength || 0
    if (!ALLOWED_ATTACHMENT_TYPES.has(contentType)) {
      log(`Skipping unsupported attachment type ${contentType} (${filename})`)
      continue
    }
    if (size > cfg.maxAttachmentBytes) {
      log(`Skipping oversized attachment ${filename} (${size} bytes)`)
      continue
    }
    const target = path.join(cfg.attachmentDir, `${hash}-${filename}`)
    await writeFile(target, attachment.content)
    saved.push({
      filename,
      contentType,
      path: target,
      uri: pathToFileURL(target).href,
      description: `Email attachment ${filename} (${contentType})`,
    })
  }
  return saved
}

async function fingerprintMatches(keydata, fingerprint) {
  if (!keydata) return false
  try {
    return (await keyFingerprint(keydata)) === fingerprint
  } catch {
    return false
  }
}

/** Find a usable verification key for an encrypted pinned-contact message. */
async function resolvePinnedVerificationKey(outerAutocrypt, pinned, knownKeyB64) {
  for (const candidate of [outerAutocrypt?.keydata, knownKeyB64]) {
    if (await fingerprintMatches(candidate, pinned.fingerprint)) return candidate
  }
  throw new Error('cannot verify encrypted message: no key with the pinned fingerprint is available')
}

/** Receive a raw RFC 822 message and return normalized text, attachments and peer key. */
export async function parseIncoming(raw, cfg, identity, log, pinned = cfg.pinned || {}, knownKeyB64 = '') {
  const rawHeaders = parseRawHeaders(raw)
  const encrypted = isEncrypted(rawHeaders)
  const sender = fromAddress(raw.toString('latin1'))
  if (pinned.contact && sender && sender !== pinned.contact) {
    throw new Error(`message from ${sender} does not match pinned contact ${pinned.contact}`)
  }

  const outerAutocrypt = parseAutocryptHeader(rawHeaders.get('autocrypt'), sender)
  let entity = raw
  let signatureVerified = false
  let verificationKeyB64 = pinned.keyB64 || ''

  if (encrypted) {
    const armored = extractArmored(raw)
    if (!armored) throw new Error('multipart/encrypted message has no PGP MESSAGE block')
    if (pinned.fingerprint && !verificationKeyB64) {
      verificationKeyB64 = await resolvePinnedVerificationKey(outerAutocrypt, pinned, knownKeyB64)
    }
    const decrypted = await decryptMessage(armored, identity, verificationKeyB64 || undefined)
    entity = decrypted.data
    signatureVerified = decrypted.signatureVerified
  } else if (pinned.requireEncrypted) {
    throw new Error('plaintext message rejected because AC_REQUIRE_ENCRYPTED is enabled')
  }

  const receiptRequest = String(
    rawHeaders.get('chat-disposition-notification-to') || rawHeaders.get('disposition-notification-to') || '',
  ).toLowerCase()
  const wantsReceipt = Boolean(cfg.address && receiptRequest.includes(String(cfg.address).toLowerCase()))
  const receipt = parseDispositionNotification(entity)

  const parsed = await simpleParser(entity, { skipHtmlToText: true, skipTextToHtml: true })
  const innerHeaders = parseRawHeaders(entity)
  const innerAutocrypt = parseAutocryptHeader(
    innerHeaders.get('autocrypt'),
    parsed.from?.value?.[0]?.address?.toLowerCase() || sender,
  )
  const autocrypt = outerAutocrypt || innerAutocrypt
  // Delta Chat MDNs have no From header in their inner entity; keep the
  // authenticated outer sender so receipts can be matched to the contact.
  const from = parsed.from?.value?.[0]?.address?.toLowerCase() || sender
  const autocryptKey = autocrypt?.keydata || ''

  if (pinned.contact && from && from !== pinned.contact) {
    throw new Error(`message from ${from} does not match pinned contact ${pinned.contact}`)
  }

  if (pinned.fingerprint) {
    if (!encrypted && !autocryptKey) {
      throw new Error('plaintext message has no Autocrypt header with the pinned fingerprint')
    }
    const candidateKey = autocryptKey || verificationKeyB64
    if (!(await fingerprintMatches(candidateKey, pinned.fingerprint))) {
      throw new Error(`Autocrypt key fingerprint does not match pinned fingerprint ${pinned.fingerprint}`)
    }
    if (pinned.keyB64 && autocryptKey && autocryptKey !== pinned.keyB64) {
      throw new Error('Autocrypt key does not match the configured pinned contact key')
    }
    if (encrypted && !signatureVerified) {
      throw new Error('encrypted message is not signed by the pinned contact key')
    }
  } else if (pinned.keyB64) {
    if (!encrypted && !autocrypt) {
      throw new Error('plaintext message has no Autocrypt header matching the pinned contact key')
    }
    if (autocrypt && autocrypt.keydata !== pinned.keyB64) {
      throw new Error('Autocrypt key does not match the pinned contact key')
    }
    if (encrypted && !signatureVerified) {
      throw new Error('encrypted message is not signed by the pinned contact key')
    }
  }

  const messageId = parsed.messageId || rawHeaders.get('message-id') || `<${createHash('sha256').update(raw).digest('hex')}@local>`
  const attachments = await saveAttachments(cfg, parsed, messageId, log)
  return {
    from,
    fromName: parsed.from?.value?.[0]?.name || '',
    messageId,
    inReplyTo: parsed.inReplyTo || rawHeaders.get('in-reply-to'),
    references: parsed.references || [],
    subject: parsed.subject || '',
    text: parsed.text || '',
    html: typeof parsed.html === 'string' ? parsed.html : '',
    attachments,
    autocrypt,
    encrypted,
    signatureVerified,
    wantsReceipt,
    mdn: receipt,
  }
}
