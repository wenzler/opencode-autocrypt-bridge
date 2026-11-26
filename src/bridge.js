import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { loadIdentity, encryptMime, keyFingerprint, validatePublicKey } from './crypto.js'
import { createSender, parseIncoming, rescanMailbox, startImap } from './mail.js'
import { buildInnerMime, buildMail, buildPgpMime, contentTypeOf, safeFilename } from './mime.js'
import {
  formatSessionDirectory,
  normalizeMessageId,
  parseNewSessionArgs,
  parseSessionCommand,
  resolveSessionRef,
  sessionFromSubject,
  withSessionSubject,
} from './session.js'

const hashId = (value) => `msg_ac_${createHash('sha256').update(String(value)).digest('hex').slice(0, 32)}`

const STATE_KEY = 'autocrypt.state'

async function loadState(ctx) {
  const stored = await ctx.storage.get(STATE_KEY)
  const data = stored && typeof stored === 'object'
    ? stored
    : { sessions: {}, peers: {}, seen: [], threads: {}, sessionContacts: {}, meta: {}, handshake: {} }
  data.sessions ||= {}
  data.peers ||= {}
  data.seen ||= []
  data.threads ||= {}
  data.sessionContacts ||= {}
  data.meta ||= {}
  data.handshake ||= {}
  return {
    data,
    async save() {
      await ctx.storage.set(STATE_KEY, data)
    },
  }
}

export async function createBridge(ctx, cfg, options = {}) {
  const log = options.log || ((message) => console.log(`[autocrypt] ${message}`))
  const onStatus = options.onStatus || (() => {})
  const identity = options.identity || await loadIdentity(ctx, cfg)

  if (cfg.pinned.contact) {
    if (cfg.pinned.keyB64) {
      const actual = await validatePublicKey(cfg.pinned.keyB64, cfg.pinned.fingerprint || undefined)
      cfg.pinned.fingerprint ||= actual
    }
    if (!cfg.pinned.fingerprint) {
      throw new Error('Pinned contact requires pinnedFingerprint')
    }
    log(`Pinned mode: only ${cfg.pinned.contact} with OpenPGP fingerprint ${cfg.pinned.fingerprint} may drive the agent`)
    if (!cfg.pinned.keyB64) log("Pinned key will be learned from the contact's Autocrypt header")
    if (cfg.pinned.requireEncrypted) log('Pinned mode: plaintext messages are rejected')
  }

  const state = await loadState(ctx)
  const store = {
    get(key) {
      return state.data.meta[key]
    },
    set(key, value) {
      state.data.meta[key] = value
      void state.save().catch((error) => log(`Failed to save IMAP checkpoint: ${error.message}`))
    },
  }
  const sender = options.sender || createSender(cfg)
  const queues = new Map()
  const controller = new AbortController()
  let started = false

  const allowed = (from) => {
    // The pin is the hard gate and takes precedence over the self-address guard.
    if (cfg.pinned.contact) return from === cfg.pinned.contact
    if (from === cfg.address) return false
    return cfg.allowedContacts.includes(from)
  }

  const enqueue = (sessionID, task) => {
    const previous = queues.get(sessionID) || Promise.resolve()
    const next = previous.then(task, task)
    queues.set(sessionID, next.catch((error) => log(`Session ${sessionID} failed: ${error.message}`)))
    return next
  }

  async function setHandshake(patch) {
    state.data.handshake = { ...state.data.handshake, ...patch, updatedAt: Date.now() }
    await state.save()
    onStatus(await getStatus())
  }

  function seenBefore(messageId) {
    return Boolean(messageId && state.data.seen.includes(messageId))
  }

  async function markSeen(messageId) {
    if (!messageId || seenBefore(messageId)) return
    state.data.seen.push(messageId)
    if (state.data.seen.length > 5_000) state.data.seen = state.data.seen.slice(-5_000)
    await state.save()
  }

  async function sessionExists(sessionID) {
    if (!sessionID) return false
    try {
      const session = await ctx.session.get({ sessionID })
      return Boolean(session?.id)
    } catch {
      return false
    }
  }

  async function rememberThread(messageId, sessionID, contact) {
    if (!messageId || !sessionID) return
    const id = normalizeMessageId(messageId)
    state.data.threads[id] = sessionID
    state.data.threads[messageId] = sessionID
    if (contact) state.data.sessionContacts[sessionID] = contact
    const keys = Object.keys(state.data.threads)
    if (keys.length > 10_000) {
      for (const key of keys.slice(0, keys.length - 10_000)) delete state.data.threads[key]
    }
    await state.save()
  }

  function threadRefs(message) {
    const references = Array.isArray(message.references)
      ? message.references
      : String(message.references || '').split(/\s+/)
    return [message.inReplyTo, ...references].filter(Boolean).map(normalizeMessageId)
  }

  async function threadSession(message) {
    for (const ref of threadRefs(message)) {
      const sessionID = state.data.threads[ref]
      if (sessionID && await sessionExists(sessionID)) return sessionID
    }
    return ''
  }

  /** Session inventory shared by the GUI, email commands and the agent tool. */
  async function listSessions() {
    let response
    try {
      response = await ctx.session.list({ limit: 100, order: 'desc' })
    } catch {
      response = await ctx.session.list()
    }
    const raw = Array.isArray(response) ? response : (response?.data || [])
    const sessions = raw.map((session) => ({
      id: String(session.id || ''),
      title: String(session.title || '(untitled)'),
      projectID: String(session.projectID || ''),
      directory: String(session.location?.directory || ''),
      agent: String(session.agent || ''),
      model: session.model ? `${session.model.providerID}/${session.model.id}` : '',
      updated: Number(session.time?.updated) || 0,
    })).filter((session) => session.id)
    const projects = new Map()
    for (const session of sessions) {
      const key = session.projectID || session.directory || 'unknown'
      if (!projects.has(key)) {
        projects.set(key, {
          id: session.projectID || '',
          directory: session.directory || '',
          sessionCount: 0,
          updated: 0,
        })
      }
      const project = projects.get(key)
      project.sessionCount += 1
      project.updated = Math.max(project.updated, session.updated)
    }
    return {
      sessions,
      projects: [...projects.values()].sort((a, b) => b.updated - a.updated),
      boundSessionID: cfg.pinned.contact ? String(state.data.sessions[cfg.pinned.contact] || '') : '',
      defaultSessionID: String(cfg.session?.defaultID || ''),
    }
  }

  async function bindSession(sessionID) {
    const candidate = String(sessionID || '').trim()
    if (!candidate) throw new Error('sessionID is required')
    const catalog = await listSessions()
    let resolved = candidate
    if (!await sessionExists(candidate)) {
      const match = resolveSessionRef(catalog.sessions, candidate)
      if (!match) throw new Error(`Unknown session "${candidate}"; use !sessions to list sessions`)
      resolved = match.id
    }
    if (cfg.pinned.contact) {
      state.data.sessions[cfg.pinned.contact] = resolved
      state.data.sessionContacts[resolved] = cfg.pinned.contact
    }
    await state.save()
    onStatus(await getStatus())
    return getStatus()
  }

  async function createAndBindSession(title, directory, bindDefault = true) {
    const catalog = await listSessions()
    const args = parseNewSessionArgs(catalog, title, directory || cfg.session?.defaultDirectory || ctx.location.directory)
    if (!args.directory || !await sessionDirectoryExists(catalog, args.directory)) {
      throw new Error(`Unknown project directory "${args.directory}"; use !sessions to list projects`)
    }
    const session = await ctx.session.create({ title: args.title, location: { directory: args.directory } })
    if (cfg.pinned.contact) {
      if (bindDefault) state.data.sessions[cfg.pinned.contact] = session.id
      state.data.sessionContacts[session.id] = cfg.pinned.contact
    }
    await state.save()
    log(`Created OpenCode session ${session.id} in ${args.directory}`)
    if (bindDefault) onStatus(await getStatus())
    return { status: await getStatus(), sessionID: session.id, title: args.title, directory: args.directory }
  }

  async function sessionDirectoryExists(catalog, directory) {
    const needle = String(directory || '').trim().toLowerCase()
    return (catalog.sessions || []).some((session) => String(session.directory || '').toLowerCase() === needle)
      || String(ctx.location.directory || '').toLowerCase() === needle
  }

  async function getStatus() {
    const peer = cfg.pinned.contact ? state.data.peers[cfg.pinned.contact] : undefined
    let learnedFingerprint = ''
    if (peer?.keydata) {
      try {
        learnedFingerprint = await keyFingerprint(peer.keydata)
      } catch {
        learnedFingerprint = ''
      }
    }
    const sessionID = cfg.pinned.contact ? String(state.data.sessions[cfg.pinned.contact] || '') : ''
    let session = null
    if (sessionID) {
      try {
        session = await ctx.session.get({ sessionID })
      } catch {}
    }
    const handshake = state.data.handshake
    return {
      running: started,
      address: cfg.address,
      pinnedContact: cfg.pinned.contact,
      pinnedFingerprint: cfg.pinned.fingerprint,
      learnedFingerprint,
      established: Boolean(handshake.established || peer?.keydata),
      verified: Boolean(handshake.verified),
      handshake: String(handshake.phase || (peer?.keydata ? 'ready' : 'idle')),
      lastError: String(handshake.lastError || ''),
      sessionID,
      sessionTitle: String(session?.title || ''),
      sessionDirectory: String(session?.location?.directory || ''),
      sessionProjectID: String(session?.projectID || ''),
    }
  }

  async function sessionFor(from) {
    const configured = String(cfg.session?.defaultID || '').trim()
    const existing = String(state.data.sessions[from] || '').trim()
    for (const candidate of [configured, existing]) {
      if (candidate && await sessionExists(candidate)) {
        state.data.sessions[from] = candidate
        state.data.sessionContacts[candidate] = from
        await state.save()
        return candidate
      }
    }
    const directory = String(cfg.session?.defaultDirectory || '').trim() || ctx.location.directory
    const session = await ctx.session.create({
      title: `Autocrypt: ${from}`,
      location: { directory },
    })
    state.data.sessions[from] = session.id
    state.data.sessionContacts[session.id] = from
    await state.save()
    log(`Created OpenCode session ${session.id} for ${from} in ${directory}`)
    return session.id
  }

  function contactForSession(sessionID) {
    if (state.data.sessionContacts[sessionID]) return state.data.sessionContacts[sessionID]
    return Object.entries(state.data.sessions).find(([, id]) => id === sessionID)?.[0]
  }

  async function learnPeer(from, autocrypt) {
    if (!autocrypt) return { learned: false, establishedNow: false }
    if (cfg.pinned.fingerprint) {
      const fingerprint = await keyFingerprint(autocrypt.keydata)
      if (fingerprint !== cfg.pinned.fingerprint) {
        log(`Ignoring Autocrypt key for ${from}: fingerprint ${fingerprint} does not match pinned fingerprint`)
        await setHandshake({ lastError: `Autocrypt fingerprint ${fingerprint} did not match the pinned fingerprint` })
        return { learned: false, establishedNow: false }
      }
    }
    const existing = state.data.peers[from]
    const learned = !existing || existing.keydata !== autocrypt.keydata
    if (learned) {
      state.data.peers[from] = {
        keydata: autocrypt.keydata,
        preferEncrypt: autocrypt.preferEncrypt,
        seenAt: Date.now(),
        autocrypt: true,
      }
      await state.save()
      log(`Learned Autocrypt key for ${from} (${autocrypt.preferEncrypt ? 'mutual' : 'nopreference'})`)
    }
    const establishedNow = !state.data.handshake.established
    if (establishedNow) {
      await setHandshake({
        phase: 'established',
        established: true,
        verified: true,
        lastError: '',
      })
    } else if (learned) {
      onStatus(await getStatus())
    }
    return { learned, establishedNow }
  }

  async function transmit({ to, text, attachments = [], inReplyTo, subject, headers = [], encrypt = true, sessionID = '' }) {
    const inner = buildInnerMime({ text, attachments })
    let body = inner.body
    let contentType = inner.contentType
    const peerKey = cfg.pinned.keyB64 || state.data.peers[to]?.keydata
    if (encrypt && peerKey) {
      try {
        const armored = await encryptMime(inner.entity, identity, [peerKey])
        const pgp = buildPgpMime(armored)
        body = pgp.body
        contentType = pgp.contentType
      } catch (error) {
        log(`Could not encrypt for ${to}, falling back to cleartext: ${error.message}`)
      }
    } else if (encrypt) {
      log(`No Autocrypt key for ${to}; sending cleartext so the peer can learn ours`)
    }
    const domain = cfg.address.split('@')[1] || 'localhost'
    const messageId = `${Date.now()}.${randomUUID()}@${domain}`
    const baseSubject = subject || (inReplyTo ? `Re: Message from ${cfg.displayName}` : `Message from ${cfg.displayName}`)
    const raw = buildMail({
      cfg,
      to,
      subject: withSessionSubject(baseSubject, sessionID),
      inReplyTo,
      messageId,
      publicB64: identity.publicB64,
      contentType,
      body,
      headers,
    })
    await sender.send(raw, to)
    if (sessionID) await rememberThread(messageId, sessionID, to)
    log(`Sent ${contentType.includes('encrypted') ? 'encrypted' : 'cleartext'} reply to ${to}${sessionID ? ` [session:${sessionID}]` : ''}`)
  }

  /** Confirm the learned key with a signed encrypted PGP/MIME reply. */
  async function sendKeyConfirmation(from, message, sessionID = '') {
    await transmit({
      to: from,
      sessionID,
      subject: `Re: ${message.subject || 'Autocrypt key confirmation'}`,
      inReplyTo: message.messageId,
      headers: ['X-OpenCode-Handshake: autocrypt-confirm'],
      encrypt: true,
      text: [
        `Key confirmed for ${from}.`,
        `Fingerprint: ${cfg.pinned.fingerprint}`,
        'OpenCode will now sign and encrypt replies to this address.',
      ].join('\n\n'),
    })
  }

  async function sendFile({ sessionID, filePath, text }) {
    const to = contactForSession(sessionID)
    if (!to) return { content: 'This session is not linked to an Autocrypt contact' }
    const root = path.resolve(ctx.location.directory)
    const target = path.resolve(root, String(filePath))
    if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
      return { content: 'Refusing to send a file outside the project directory' }
    }
    const content = await readFile(target)
    const filename = safeFilename(path.basename(target))
    await transmit({
      to,
      sessionID,
      text: String(text || ''),
      attachments: [{ filename, contentType: contentTypeOf(filename), content }],
    })
    return { content: `Sent ${filename} to ${to}` }
  }

  async function startAutocryptHandshake(force = false) {
    if (!cfg.pinned.contact) throw new Error('Autocrypt handshake requires pinnedContact')
    if (!force && state.data.peers[cfg.pinned.contact]?.keydata) {
      await setHandshake({ phase: 'ready', established: true, lastError: '' })
      return getStatus()
    }
    await setHandshake({ phase: 'awaiting-reply', established: false, verified: false, lastError: '' })
    await transmit({
      to: cfg.pinned.contact,
      subject: `Connect ${cfg.displayName}`,
      text: [
        `Hello from ${cfg.displayName}.`,
        'Please reply to this message once so OpenCode can learn your public key.',
        'The key is accepted only if its fingerprint matches the pinned value.',
      ].join('\n\n'),
      headers: ['X-OpenCode-Handshake: autocrypt-request'],
      encrypt: false,
    })
    return getStatus()
  }

  async function sendCommandReply(from, message, sessionID, text, kind = 'session-command') {
    await transmit({
      to: from,
      sessionID,
      subject: `Re: ${message.subject || 'OpenCode session'}`,
      inReplyTo: message.messageId,
      headers: [`X-OpenCode-Command: ${kind}`],
      text,
    })
  }

  /** Choose the OpenCode session for one inbound email. */
  async function resolveInboundSession(from, message, command) {
    if (command?.command === 'use') {
      const catalog = await listSessions()
      const match = resolveSessionRef(catalog.sessions, command.argument)
      if (!match) throw new Error(`Unknown session "${command.argument}"; use !sessions to list sessions`)
      await rememberThread(message.messageId, match.id, from)
      return { sessionID: match.id, reason: 'use', note: `Using session ${match.id} (${match.title})` }
    }
    if (command?.command === 'new') {
      const fallback = await sessionFor(from)
      let current = null
      try {
        current = await ctx.session.get({ sessionID: fallback })
      } catch {}
      const created = await createAndBindSession(command.argument, current?.location?.directory, false)
      await rememberThread(message.messageId, created.sessionID, from)
      return {
        sessionID: created.sessionID,
        reason: 'new',
        note: `Created session ${created.sessionID} (${created.title}) in ${created.directory}`,
      }
    }
    if (command?.command === 'default') {
      const target = await sessionFor(from)
      await rememberThread(message.messageId, target, from)
      return { sessionID: target, reason: 'default', note: `Returned to default session ${target}` }
    }

    // Delta Chat keeps the subject on replies, so the marker is the strongest
    // signal. Threading headers are the fallback for other mail clients.
    const subjectSessionID = sessionFromSubject(message.subject)
    if (subjectSessionID && await sessionExists(subjectSessionID)) {
      state.data.sessionContacts[subjectSessionID] = from
      await state.save()
      return { sessionID: subjectSessionID, reason: 'subject' }
    }
    const threaded = await threadSession(message)
    if (threaded) return { sessionID: threaded, reason: 'thread' }
    return { sessionID: await sessionFor(from), reason: 'default' }
  }

  async function commandReplyText(command, catalog, sessionID, resolution) {
    if (command.command === 'sessions' || command.command === 'help') {
      return formatSessionDirectory(catalog, sessionID)
    }
    if (command.command === 'status') {
      const status = await getStatus()
      return [
        `Email-bound session: ${status.sessionID || '(none)'}`,
        `Title: ${status.sessionTitle || '(untitled)'}`,
        `Directory: ${status.sessionDirectory || '(unknown)'}`,
        `Project: ${status.sessionProjectID || '(none)'}`,
        `This thread's session: ${sessionID}`,
        `Established: ${status.established ? 'yes' : 'no'}`,
      ].join('\n')
    }
    return `${resolution.note || `Using session ${sessionID}`}.\n\nFurther replies in this subject stay in this session.`
  }

  const LOCAL_COMMANDS = new Set(['sessions', 'help', 'status', 'use', 'new', 'default'])

  async function handle(raw) {
    let message
    try {
      message = await parseIncoming(
        raw,
        cfg,
        identity,
        log,
        cfg.pinned,
        state.data.peers[cfg.pinned.contact]?.keydata,
      )
    } catch (error) {
      log(`Rejected message: ${error.message}`)
      return
    }
    const from = String(message.from || '').toLowerCase()
    if (!from || !allowed(from)) {
      log(`Ignoring message from ${from || 'unknown'}`)
      return
    }
    if (seenBefore(message.messageId)) return
    await markSeen(message.messageId)

    const command = parseSessionCommand(message.text)
    const { establishedNow } = await learnPeer(from, message.autocrypt)
    let resolution
    try {
      resolution = await resolveInboundSession(from, message, command)
    } catch (error) {
      log(`Session command failed: ${error.message}`)
      const fallback = await sessionFor(from)
      await rememberThread(message.messageId, fallback, from)
      await sendCommandReply(from, message, fallback, `Error: ${error.message}`, 'error')
      return
    }
    const sessionID = resolution.sessionID
    await rememberThread(message.messageId, sessionID, from)

    if (establishedNow) {
      try {
        await sendKeyConfirmation(from, message, sessionID)
      } catch (error) {
        log(`Could not send key confirmation: ${error.message}`)
      }
    }

    if (command && LOCAL_COMMANDS.has(command.command)) {
      const catalog = await listSessions()
      const text = await commandReplyText(command, catalog, sessionID, resolution)
      if (!command.rest) {
        await sendCommandReply(from, message, sessionID, text)
        return
      }
      // `!use <id> question` switches the thread and asks in one email.
      command.rest = `${resolution.note || `Using session ${sessionID}`}\n\n${command.rest}`
    }

    await enqueue(sessionID, async () => {
      const files = message.attachments.map((attachment) => ({
        uri: attachment.uri,
        name: attachment.filename,
        description: attachment.description,
      }))
      const promptId = hashId(message.messageId)
      const text = [
        command?.rest || message.text || '(message contained no plain text)',
        `[Autocrypt email from ${from}${message.fromName ? ` (${message.fromName})` : ''}]`,
        `[OpenCode session: ${sessionID}${resolution.note ? ` — ${resolution.note}` : ''}]`,
        ...(message.attachments.length ? [`[Attachments: ${message.attachments.map((a) => a.filename).join(', ')}]`] : []),
      ].join('\n\n')
      const promptResult = await ctx.session.prompt({
        sessionID,
        id: promptId,
        text,
        ...(files.length ? { files } : {}),
        metadata: { source: 'autocrypt-email', from, messageId: message.messageId, sessionID },
      })
      const userMessageID = promptResult?.id || promptId
      await ctx.session.wait({ sessionID })
      const messages = await ctx.session.context({ sessionID })
      const index = messages.findIndex((entry) => entry.id === userMessageID)
      const replies = (index < 0 ? [] : messages.slice(index + 1))
        .filter((entry) => entry.type === 'assistant' && !entry.error)
        .flatMap((entry) => entry.content.filter((part) => part.type === 'text').map((part) => part.text))
        .join('\n\n')
        .trim()
      if (replies) await transmit({ to: from, text: replies, inReplyTo: message.messageId, sessionID })
      else log(`No assistant text to send to ${from}`)
    })
  }

  async function rescanInbox() {
    const result = await rescanMailbox(cfg, store, handle, log, controller.signal)
    log(`Rescanned ${result.total} mailbox message(s); handled ${result.processed}`)
    onStatus(await getStatus())
    return getStatus()
  }

  async function resetContact() {
    delete state.data.peers[cfg.pinned.contact]
    state.data.handshake = { phase: 'idle', established: false, verified: false, lastError: '' }
    await state.save()
    onStatus(await getStatus())
    return getStatus()
  }

  return {
    start() {
      if (started) return
      started = true
      log(`Listening for Autocrypt mail at ${cfg.address} (${cfg.imap.mailbox})`)
      void startImap(cfg, store, handle, controller.signal, log)
      if (cfg.pinned.contact && !state.data.peers[cfg.pinned.contact]?.keydata) {
        const last = Number(state.data.meta.autocryptBootstrapAt || 0)
        if (!last || Date.now() - last > 24 * 60 * 60 * 1000) {
          state.data.meta.autocryptBootstrapAt = Date.now()
          void state.save()
          const bootstrap = startAutocryptHandshake(true)
          void bootstrap.catch((error) => log(`Contact bootstrap failed: ${error.message}`))
        }
      }
      onStatus(getStatus())
    },
    stop() {
      controller.abort()
      started = false
      onStatus(getStatus())
      log('Stopped')
    },
    // Exposed for tests and for local loopback checks against a real mail server.
    process: handle,
    getStatus,
    async startHandshake() {
      return startAutocryptHandshake(true)
    },
    rescanInbox,
    resetContact,
    listSessions,
    bindSession,
    createAndBindSession,
    sendFile,
    getIdentity: () => identity,
  }
}
