import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import {
  classifyPermission,
  decisionCode,
  formatDecisionRequest,
  formatPeek,
  formatQuestionRequest,
  formatRemoteHelp,
  parseQuestionAnswers,
} from './commands.js'
import {
  decryptMessageWithPassword,
  encryptMimeWithPassword,
  encryptMime,
  keyFingerprint,
  loadIdentity,
  validatePublicKey,
} from './crypto.js'
import { createSender, parseIncoming, rescanMailbox, secureJoinFrom, startImap } from './mail.js'
import {
  buildInnerMime,
  buildMail,
  buildPgpMime,
  buildReadReceiptMime,
  contentTypeOf,
  extractArmored,
  headerValues,
  parseRawHeaders,
  safeFilename,
} from './mime.js'
import { autocryptGossipHeader, autocryptHeader } from './headers.js'
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
    : {
      sessions: {}, peers: {}, seen: [], threads: {}, sessionContacts: {}, meta: {}, handshake: {},
      watches: {}, pending: {}, questions: {}, sent: {},
    }
  data.sessions ||= {}
  data.peers ||= {}
  data.seen ||= []
  data.threads ||= {}
  data.sessionContacts ||= {}
  data.meta ||= {}
  data.handshake ||= {}
  data.watches ||= {}
  data.pending ||= {}
  data.questions ||= {}
  data.sent ||= {}
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
  const onQuestion = options.onQuestion || (() => {})
  const onQuestionAnswer = options.onQuestionAnswer || (() => {})
  const identity = options.identity || await loadIdentity(ctx, cfg)
  const selfFingerprint = await keyFingerprint(identity.publicB64)

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
  const inFlight = new Set()
  const sessionStatus = new Map()
  const lastWatchNotify = new Map()
  const announcedDecisions = new Set()
  const announcingQuestions = new Set()
  let started = false

  const WATCH_EVENTS = [
    'permission.asked',
    'permission.replied',
    'form.created',
    'form.replied',
    'form.cancelled',
    'session.status',
    'session.idle',
    'session.execution.succeeded',
    'session.execution.failed',
    'session.step.failed',
  ]

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
    const lastReceiptAt = Math.max(0, ...Object.values(state.data.sent)
      .map((entry) => Number(entry?.receiptAt) || 0))
    return {
      running: started,
      remoteMode: cfg.remote.mode,
      address: cfg.address,
      selfFingerprint,
      pinnedContact: cfg.pinned.contact,
      pinnedFingerprint: cfg.pinned.fingerprint,
      learnedFingerprint,
      established: Boolean(handshake.established || peer?.keydata),
      verified: Boolean(handshake.verified),
      handshake: String(handshake.phase || (peer?.keydata ? 'ready' : 'idle')),
      secureJoin: {
        status: String(handshake.secureJoin?.status || 'idle'),
        address: String(handshake.secureJoin?.address || ''),
        fingerprint: String(handshake.secureJoin?.fingerprint || ''),
        createdAt: Number(handshake.secureJoin?.createdAt || 0),
      },
      lastError: String(handshake.lastError || ''),
      sessionID,
      sessionTitle: String(session?.title || ''),
      sessionDirectory: String(session?.location?.directory || ''),
      sessionProjectID: String(session?.projectID || ''),
      lastReceiptAt,
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

  async function sessionRoot(sessionID) {
    if (sessionID) {
      try {
        const session = await ctx.session.get({ sessionID })
        if (session?.location?.directory) return path.resolve(String(session.location.directory))
      } catch {}
    }
    return path.resolve(String(cfg.session?.defaultDirectory || ctx.location.directory || '.'))
  }

  const normalizeCode = (value) => String(value || '').trim().toUpperCase().replace(/^D-/, '')

  /** Keep form events small and stable across the RPC and IPC boundaries. */
  function formFieldView(fields) {
    return (Array.isArray(fields) ? fields : []).map((field, index) => ({
      key: String(field?.key || `q${index}`),
      title: String(field?.title || field?.description || `Question ${index + 1}`),
      description: field?.description ? String(field.description) : '',
      type: String(field?.type || (Array.isArray(field?.options) ? 'select' : 'string')),
      options: (Array.isArray(field?.options) ? field.options : []).map((option, optionIndex) => ({
        value: String(option?.value ?? option?.label ?? optionIndex + 1),
        label: String(option?.label ?? option?.value ?? optionIndex + 1),
        description: option?.description ? String(option.description) : '',
      })),
    }))
  }

  function findPending(collection, from, code) {
    const needle = normalizeCode(code)
    if (!needle) return undefined
    return Object.values(collection).find((entry) => (
      entry
      && !entry.answered
      && entry.from === from
      && (normalizeCode(entry.code) === needle
        || String(entry.requestID || entry.formID || '').toLowerCase().startsWith(needle.toLowerCase()))
    ))
  }

  function watchersFor(sessionID) {
    const contacts = new Set()
    for (const [contact, watch] of Object.entries(state.data.watches)) {
      if (watch?.sessionID === sessionID && allowed(contact)) contacts.add(contact)
    }
    return [...contacts]
  }

  async function sendSessionNotice(sessionID, subject, text, kind = 'session-notice') {
    const recipients = watchersFor(sessionID)
    for (const to of recipients) {
      await transmit({
        to,
        sessionID,
        subject,
        headers: [`X-OpenCode-Notice: ${kind}`],
        text,
      })
    }
  }

  async function handlePermissionAsked(data = {}) {
    const requestID = String(data.id || data.requestID || '')
    if (!requestID || announcedDecisions.has(requestID) || state.data.pending[requestID]) return
    const sessionID = String(data.sessionID || '')
    const to = contactForSession(sessionID) || cfg.pinned.contact
    if (!to || !allowed(to)) return
    announcedDecisions.add(requestID)
    const resources = Array.isArray(data.resources) ? data.resources.map(String) : []
    const risk = classifyPermission(data.action, resources, await sessionRoot(sessionID))
    const code = decisionCode(requestID)
    const options = Array.isArray(data.save) && data.save.length
      ? ['once', 'always', 'reject']
      : ['once', 'reject']
    state.data.pending[requestID] = {
      requestID,
      code,
      sessionID,
      from: to,
      action: String(data.action || ''),
      resources,
      risk,
      options,
      createdAt: Date.now(),
      answered: false,
    }
    await state.save()
    try {
      await transmit({
        to,
        sessionID,
        subject: `Decision needed: ${data.action || 'permission'}`,
        headers: [`X-OpenCode-Decision: ${code}`],
        text: formatDecisionRequest({
          code,
          action: data.action,
          resources,
          risk,
          enabled: Boolean(cfg.remote.decisions),
          canAnswer: Boolean(cfg.remote.decisions) && (risk.level !== 'high' || cfg.remote.highRiskDecisions),
          highRiskAllowed: Boolean(cfg.remote.highRiskDecisions),
          options,
          sessionID,
        }),
      })
    } catch (error) {
      log(`Could not send decision mail: ${error.message}`)
    }
  }

  async function handlePermissionReplied(data = {}) {
    const requestID = String(data.requestID || data.id || '')
    const pending = state.data.pending[requestID]
    if (!pending || pending.answered) return
    pending.answered = true
    pending.repliedAt = Date.now()
    await state.save()
  }

  async function handleFormCreated(data = {}) {
    const form = data.form || {}
    const formID = String(form.id || '')
    if (!formID || announcingQuestions.has(formID) || state.data.questions[formID]) return
    if (String(form.metadata?.kind || '') !== 'question') return
    if (!cfg.remote.questions) return
    const sessionID = String(form.sessionID || '')
    const to = contactForSession(sessionID) || cfg.pinned.contact
    if (!to || !allowed(to)) return
    announcingQuestions.add(formID)
    try {
      const fields = formFieldView(form.fields)
      const code = decisionCode(formID)
      state.data.questions[formID] = {
        formID,
        code,
        sessionID,
        from: to,
        title: String(form.title || 'Questions'),
        fields,
        createdAt: Date.now(),
        answered: false,
      }
      await state.save()
      try {
        await onQuestion({
          formID,
          code,
          sessionID,
          title: state.data.questions[formID].title,
          fields: state.data.questions[formID].fields,
        })
      } catch (error) {
        log(`Could not notify the GUI about a question: ${error.message}`)
      }
      try {
        await transmit({
          to,
          sessionID,
          subject: `Question: ${form.title || 'OpenCode'}`,
          headers: [`X-OpenCode-Question: ${code}`],
          text: formatQuestionRequest({ code, title: form.title, fields, sessionID }),
        })
      } catch (error) {
        log(`Could not send question mail: ${error.message}`)
      }
    } finally {
      announcingQuestions.delete(formID)
    }
  }

  async function handleFormSettled(data = {}) {
    const formID = String(data.id || data.formID || '')
    const pending = state.data.questions[formID]
    if (!pending || pending.answered) return
    pending.answered = true
    pending.repliedAt = Date.now()
    await state.save()
  }

  async function handleSessionEvent(event) {
    const data = event.data || {}
    const sessionID = String(data.sessionID || '')
    if (!sessionID) return
    if (event.type === 'session.status') {
      sessionStatus.set(sessionID, String(data.status?.type || 'idle'))
    } else if (event.type === 'session.idle') {
      sessionStatus.set(sessionID, 'idle')
    }
    if (!cfg.remote.watch || inFlight.has(sessionID)) return
    const last = Number(lastWatchNotify.get(sessionID) || 0)
    if (Date.now() - last < 30_000) return
    let subject = ''
    let text = ''
    let kind = 'session-notice'
    if (event.type === 'session.status') {
      if (data.status?.type !== 'idle') return
      subject = `Session idle: ${sessionID}`
      text = `Session ${sessionID} is idle.`
      kind = 'idle'
    } else if (event.type === 'session.idle') {
      subject = `Session idle: ${sessionID}`
      text = `Session ${sessionID} is idle.`
      kind = 'idle'
    } else if (event.type === 'session.execution.failed' || event.type === 'session.step.failed') {
      const error = data.error?.message || data.error || 'unknown error'
      subject = `Session failed: ${sessionID}`
      text = `Session ${sessionID} failed: ${error}`
      kind = 'failure'
    } else if (event.type === 'session.execution.succeeded') {
      subject = `Session finished: ${sessionID}`
      text = `Session ${sessionID} finished. Use !peek to read the result.`
      kind = 'success'
    } else {
      return
    }
    if (!watchersFor(sessionID).length) return
    lastWatchNotify.set(sessionID, Date.now())
    await sendSessionNotice(sessionID, subject, text, kind)
  }

  async function handleEvent(event) {
    const data = event.data || {}
    switch (event.type) {
      case 'permission.asked': return handlePermissionAsked(data)
      case 'permission.replied': return handlePermissionReplied(data)
      case 'form.created': return handleFormCreated(data)
      case 'form.replied':
      case 'form.cancelled': return handleFormSettled(data)
      case 'session.status':
      case 'session.idle':
      case 'session.execution.succeeded':
      case 'session.execution.failed':
      case 'session.step.failed': return handleSessionEvent(event)
      default: return undefined
    }
  }

  function startEvents() {
    if (!ctx.event?.subscribe || typeof ctx.event.subscribe !== 'function') return
    void (async () => {
      for await (const event of ctx.event.subscribe({ types: WATCH_EVENTS, signal: controller.signal })) {
        void handleEvent(event).catch((error) => log(`Event ${event.type} failed: ${error.message}`))
      }
    })().catch((error) => {
      if (!controller.signal.aborted) log(`Event subscription stopped: ${error.message}`)
    })
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

  async function protect(inner, to, encrypt = true, explicitPeerKey = '') {
    let body = inner.body
    let contentType = inner.contentType
    const peerKey = explicitPeerKey || cfg.pinned.keyB64 || state.data.peers[to]?.keydata
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
    return { body, contentType }
  }

  async function rememberSent(messageId, to, sessionID, subject) {
    const id = normalizeMessageId(messageId)
    if (!id) return
    state.data.sent[id] = {
      messageID: id,
      to,
      sessionID,
      subject,
      sentAt: Date.now(),
      receiptAt: 0,
    }
    const keys = Object.keys(state.data.sent)
    if (keys.length > 2_000) {
      for (const key of keys.slice(0, keys.length - 2_000)) delete state.data.sent[key]
    }
    await state.save()
  }

  async function transmit({ to, text, attachments = [], inReplyTo, subject, headers = [], encrypt = true, sessionID = '' }) {
    const protectedBody = await protect(buildInnerMime({ text, attachments }), to, encrypt)
    const domain = cfg.address.split('@')[1] || 'localhost'
    const messageId = `${Date.now()}.${randomUUID()}@${domain}`
    const baseSubject = subject || (inReplyTo ? `Re: Message from ${cfg.displayName}` : `Message from ${cfg.displayName}`)
    const finalSubject = withSessionSubject(baseSubject, sessionID)
    const receiptHeaders = cfg.remote?.readReceipts === false
      ? []
      : [`Chat-Disposition-Notification-To: ${cfg.address}`]
    const raw = buildMail({
      cfg,
      to,
      subject: finalSubject,
      inReplyTo,
      messageId,
      publicB64: identity.publicB64,
      contentType: protectedBody.contentType,
      body: protectedBody.body,
      headers: [...headers, ...receiptHeaders],
    })
    await sender.send(raw, to)
    await rememberSent(messageId, to, sessionID, finalSubject)
    if (sessionID) await rememberThread(messageId, sessionID, to)
    log(`Sent ${protectedBody.contentType.includes('encrypted') ? 'encrypted' : 'cleartext'} reply to ${to}${sessionID ? ` [session:${sessionID}]` : ''}`)
  }

  /** Send a Delta Chat-compatible MDN for a message that requested one. */
  async function sendReadReceipt(to, originalMessageID) {
    if (cfg.remote?.readReceipts === false) return
    const receipt = buildReadReceiptMime({ originalMessageID })
    const protectedBody = await protect(receipt, to)
    const domain = cfg.address.split('@')[1] || 'localhost'
    const messageId = `${Date.now()}.${randomUUID()}@${domain}`
    const id = normalizeMessageId(originalMessageID).replace(/[\r\n]/g, '')
    const raw = buildMail({
      cfg,
      to,
      subject: 'Receipt Notification',
      messageId,
      publicB64: identity.publicB64,
      contentType: protectedBody.contentType,
      body: protectedBody.body,
      headers: [
        'Auto-Submitted: auto-replied',
        `X-OpenCode-Read-Receipt: ${id}`,
      ],
    })
    await sender.send(raw, to)
    log(`Sent read receipt to ${to} for ${id}`)
  }

  async function handleReadReceipt(from, receipt) {
    const id = normalizeMessageId(receipt?.originalMessageID)
    if (!id) return
    const entry = state.data.sent[id]
    if (!entry || entry.to !== from || entry.receiptAt) return
    entry.receiptAt = Date.now()
    await state.save()
    log(`Read receipt confirmed from ${from} for ${id}`)
  }

  /** Send the one-time encrypted welcome mail with the full command list. */
  async function maybeSendWelcome(from, message, sessionID = '') {
    const flag = `welcome:${from}:${cfg.pinned.fingerprint}`
    if (state.data.meta[flag]) return
    const status = await getStatus()
    if (!status.established || !status.verified) return
    await transmit({
      to: from,
      sessionID,
      subject: `Re: ${message.subject || 'Connected'}`,
      inReplyTo: message.messageId,
      headers: ['X-OpenCode-Handshake: autocrypt-confirm', 'X-OpenCode-Command: help'],
      encrypt: true,
      text: [
        `Key confirmed for ${from}.`,
        `Fingerprint: ${cfg.pinned.fingerprint}`,
        'OpenCode will now sign and encrypt replies to this address.',
        '',
        formatRemoteHelp(cfg.remote, {
          sessionID,
          sessionTitle: status.sessionTitle,
        }),
      ].join('\n'),
    })
    state.data.meta[flag] = Date.now()
    await state.save()
  }

  async function sendFile({ sessionID, filePath, text }) {
    const to = contactForSession(sessionID)
    if (!to) return { content: 'This session is not linked to an Autocrypt contact' }
    const root = await sessionRoot(sessionID)
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

  /** SecureJoin v3: the QR advertises this bridge (Alice), not the pinned peer. */
  function secureJoinSecret(auth) {
    return `securejoin/${selfFingerprint}/${auth}`
  }

  function pendingSecureJoin() {
    if (cfg.remote.mode !== 'securejoin') return undefined
    const invite = state.data.handshake.secureJoin
    if (!invite || !invite.auth || invite.fingerprint !== selfFingerprint) return undefined
    if (invite.address && invite.address !== cfg.pinned.contact) return undefined
    if (Date.now() - Number(invite.createdAt || 0) > 60 * 60 * 1000) return undefined
    return invite
  }

  async function getSecureJoinQr() {
    if (cfg.remote.mode !== 'securejoin') {
      throw new Error('SecureJoin QR is only available in SecureJoin remote mode')
    }
    if (!cfg.pinned.contact || !cfg.pinned.fingerprint) {
      throw new Error('SecureJoin requires pinnedContact and pinnedFingerprint')
    }
    const auth = randomBytes(18).toString('base64url')
    state.data.handshake.secureJoin = {
      auth,
      address: cfg.pinned.contact,
      fingerprint: selfFingerprint,
      createdAt: Date.now(),
      status: 'awaiting-scan',
    }
    await state.save()
    const uri = `OPENPGP4FPR:${selfFingerprint}`
      + `#a=${encodeURIComponent(cfg.pinned.contact)}`
      + `&n=${encodeURIComponent(cfg.displayName || 'OpenCode')}`
      + `&s=${auth}&v=3`
    onStatus(await getStatus())
    return {
      uri,
      fingerprint: selfFingerprint,
      address: cfg.pinned.contact,
      status: 'awaiting-scan',
    }
  }

  async function sendSecureJoinPubkey(to, auth) {
    const inner = buildInnerMime({
      text: 'Secure-Join',
      headers: [
        `From: "${String(cfg.displayName || '').replace(/"/g, '')}" <${cfg.address}>`,
        `To: <${to}>`,
        'Subject: Secure-Join',
        'Secure-Join: vc-pubkey',
        `Secure-Join-Auth: ${auth}`,
        `Autocrypt: ${autocryptHeader(cfg.address, identity.publicB64, true)}`,
        'Chat-Version: 1.0',
      ],
    })
    const armored = await encryptMimeWithPassword(inner.entity, secureJoinSecret(auth), identity)
    const pgp = buildPgpMime(armored)
    const messageId = `${Date.now()}.${randomUUID()}@${cfg.address.split('@')[1] || 'localhost'}`
    const raw = buildMail({
      cfg,
      to,
      subject: 'Chat: Secure-Join',
      messageId,
      publicB64: identity.publicB64,
      contentType: pgp.contentType,
      body: pgp.body,
      headers: [
        'Secure-Join: vc-pubkey',
        `Secure-Join-Auth: ${auth}`,
        'X-OpenCode-SecureJoin: vc-pubkey',
      ],
    })
    await sender.send(raw, to)
    log(`Sent SecureJoin vc-pubkey to ${to}`)
  }

  async function sendSecureJoinConfirm(to, auth, peerKeyB64) {
    const inner = buildInnerMime({
      text: 'Secure-Join',
      headers: [
        `From: "${String(cfg.displayName || '').replace(/"/g, '')}" <${cfg.address}>`,
        `To: <${to}>`,
        'Subject: Secure-Join',
        'Secure-Join: vc-contact-confirm',
        `Secure-Join-Fingerprint: ${cfg.pinned.fingerprint}`,
        `Autocrypt: ${autocryptHeader(cfg.address, identity.publicB64, true)}`,
        `Autocrypt-Gossip: ${autocryptGossipHeader(to, peerKeyB64)}`,
        'Chat-Version: 1.0',
      ],
    })
    const protectedBody = await protect(inner, to, true, peerKeyB64)
    const messageId = `${Date.now()}.${randomUUID()}@${cfg.address.split('@')[1] || 'localhost'}`
    const raw = buildMail({
      cfg,
      to,
      subject: 'Chat: Secure-Join',
      messageId,
      publicB64: identity.publicB64,
      contentType: protectedBody.contentType,
      body: protectedBody.body,
      headers: [
        'Secure-Join: vc-contact-confirm',
        `Secure-Join-Fingerprint: ${cfg.pinned.fingerprint}`,
        'X-OpenCode-SecureJoin: vc-contact-confirm',
      ],
    })
    await sender.send(raw, to)
    log(`Sent SecureJoin vc-contact-confirm to ${to}`)
  }

  /** Alice side of SecureJoin v3. Returns true when the raw message was consumed. */
  async function handleSecureJoinRequestPubkey(raw) {
    const invite = pendingSecureJoin()
    if (!invite) return false
    const outer = parseRawHeaders(raw)
    const from = String(outer.get('from') || '')
    const senderAddress = /<([^<>\s@]+@[^<>\s>]+)>/.exec(from)?.[1]?.toLowerCase()
      || /([^<>\s@]+@[^<>\s>]+)/.exec(from)?.[1]?.toLowerCase()
    if (senderAddress && senderAddress !== cfg.pinned.contact) return false
    const armored = extractArmored(raw)
    if (!armored) return false
    let entity
    try {
      entity = await decryptMessageWithPassword(armored, secureJoinSecret(invite.auth), cfg.pinned.keyB64)
    } catch {
      return false
    }
    const inner = parseRawHeaders(entity)
    const step = secureJoinFrom(outer, inner)
    if (step?.step !== 'vc-request-pubkey' || step.auth !== invite.auth) return false

    const fromName = String(state.data.peers[cfg.pinned.contact]?.name || cfg.displayName || 'OpenCode')
    state.data.peers[cfg.pinned.contact] ||= {}
    state.data.peers[cfg.pinned.contact].keydata ||= cfg.pinned.keyB64
    state.data.peers[cfg.pinned.contact].name ||= fromName
    state.data.handshake.secureJoin.status = 'pubkey-sent'
    await state.save()
    await sendSecureJoinPubkey(cfg.pinned.contact, invite.auth)
    onStatus(await getStatus())
    return true
  }

  async function handleSecureJoinRequestWithAuth(from, message) {
    const invite = pendingSecureJoin()
    if (!invite || message.secureJoin?.step !== 'vc-request-with-auth') return false
    if (message.secureJoin.auth !== invite.auth) {
      log('Ignoring SecureJoin request with an unknown auth code')
      return false
    }
    const announced = String(message.secureJoin.fingerprint || '').replace(/[^0-9a-f]/gi, '').toUpperCase()
    if (announced !== cfg.pinned.fingerprint) {
      log(`Ignoring SecureJoin fingerprint ${announced || '(missing)'}`)
      return false
    }
    if (!message.signatureVerified || !message.encrypted) {
      log('Ignoring unsigned or unencrypted SecureJoin request')
      return false
    }
    const peerKey = message.autocrypt?.keydata || cfg.pinned.keyB64
    if (!peerKey) {
      log('Ignoring SecureJoin request without a usable pinned contact key')
      return false
    }
    let peerFingerprint = ''
    try {
      peerFingerprint = await keyFingerprint(peerKey)
    } catch {
      log('Ignoring SecureJoin request with an unreadable contact key')
      return false
    }
    if (peerFingerprint !== cfg.pinned.fingerprint) {
      log(`Ignoring SecureJoin key fingerprint ${peerFingerprint}`)
      return false
    }
    state.data.peers[from] ||= {}
    state.data.peers[from].keydata = peerKey
    state.data.peers[from].fingerprint = peerFingerprint
    state.data.peers[from].name ||= message.fromName || ''
    state.data.peers[from].seenAt = Date.now()
    state.data.handshake.secureJoin.status = 'confirm-sent'
    await state.save()
    await sendSecureJoinConfirm(from, invite.auth, peerKey)
    state.data.handshake.secureJoin.verified = true
    state.data.handshake.secureJoin.status = 'verified'
    await state.save()
    await setHandshake({
      phase: 'verified',
      established: true,
      verified: true,
      lastError: '',
    })
    log(`SecureJoin verified ${from} with fingerprint ${cfg.pinned.fingerprint}`)
    onStatus(await getStatus())
    return true
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

  async function answerDecision(from, message, command) {
    if (!cfg.remote.decisions) {
      await sendCommandReply(from, message, '', 'Permission decisions by email are disabled in Settings → Autocrypt Bridge → Remote controls.', 'error')
      return
    }
    const pending = findPending(state.data.pending, from, command.argument)
    if (!pending) {
      await sendCommandReply(from, message, '', `Unknown decision code "${command.argument || ''}". Use the code in the decision email.`, 'error')
      return
    }
    if (pending.risk.level === 'high' && !cfg.remote.highRiskDecisions) {
      await sendCommandReply(from, message, pending.sessionID, [
        `Decision ${pending.code} is HIGH RISK: ${pending.risk.reasons.join('; ') || pending.action}.`,
        'Email approval is disabled for high-risk requests.',
        'Enable it in Settings → Autocrypt Bridge → Remote controls, or answer at the desktop.',
      ].join('\n'), 'error')
      return
    }
    const wantsAlways = /\balways\b/i.test(command.rest)
    const decision = command.command === 'deny'
      ? 'reject'
      : (wantsAlways && pending.options.includes('always') ? 'always' : 'once')
    const note = decision === 'reject' ? command.rest.trim() : ''
    try {
      await ctx.permission.reply({
        sessionID: pending.sessionID,
        requestID: pending.requestID,
        decision,
        ...(note ? { message: note } : {}),
      })
    } catch (error) {
      await sendCommandReply(from, message, pending.sessionID, `Could not record the decision: ${error.message}`, 'error')
      return
    }
    pending.answered = true
    pending.repliedAt = Date.now()
    await state.save()
    await sendCommandReply(from, message, pending.sessionID, `Decision recorded: ${decision} for ${pending.code}. The desktop session can continue.`)
  }

  async function answerQuestion(from, message, command) {
    if (!cfg.remote.questions) {
      await sendCommandReply(from, message, '', 'Multiple-choice answers by email are disabled in Settings → Autocrypt Bridge → Remote controls.', 'error')
      return
    }
    const pending = findPending(state.data.questions, from, command.argument)
    if (!pending) {
      await sendCommandReply(from, message, '', `Unknown question code "${command.argument || ''}". Use the code in the question email.`, 'error')
      return
    }
    const parsed = parseQuestionAnswers(pending.fields, command.rest)
    if (parsed.error) {
      await sendCommandReply(from, message, pending.sessionID, `${parsed.error}\n\nUse: !answer ${pending.code} 1`, 'error')
      return
    }
    if (pending.submittedAt) return
    const entries = Object.entries(parsed.answer).map(([key, value]) => ({ key, value }))
    pending.submittedAt = Date.now()
    pending.lastAnswer = entries
    pending.completionNotified = false
    await state.save()
    try {
      await onQuestionAnswer({
        formID: pending.formID,
        sessionID: pending.sessionID,
        answer: entries,
      })
    } catch (error) {
      pending.submittedAt = 0
      pending.completionNotified = false
      await state.save()
      await sendCommandReply(from, message, pending.sessionID, `Could not forward the answer: ${error.message}`, 'error')
    }
  }

  async function confirmQuestionReply({ formID, ok, error = '' }) {
    const pending = state.data.questions[String(formID || '')]
    if (!pending || pending.completionNotified) return
    if (!ok && (pending.answered || pending.repliedAt)) return
    pending.completionNotified = true
    if (ok) {
      pending.answered = true
      pending.repliedAt = Date.now()
      await state.save()
      await transmit({
        to: pending.from,
        sessionID: pending.sessionID,
        subject: `Re: Question: ${pending.title}`,
        headers: ['X-OpenCode-Command: question-answered'],
        text: `Question ${pending.code} was completed on the desktop. The session can continue.`,
      })
      return
    }
    pending.submittedAt = 0
    pending.repliedAt = 0
    await state.save()
    await transmit({
      to: pending.from,
      sessionID: pending.sessionID,
      subject: `Re: Question: ${pending.title}`,
      headers: ['X-OpenCode-Command: error'],
      text: [
        `The desktop could not complete question ${pending.code}: ${error || 'unknown error'}`,
        '',
        `Retry with the same choices: !answer ${pending.code} <choice>`,
      ].join('\n'),
    })
  }

  async function localCommandReply(from, message, command, catalog, sessionID, resolution) {
    switch (command.command) {
      case 'sessions':
        return `${formatSessionDirectory(catalog, catalog.boundSessionID)}\n\nUse !help for the full remote-control list.`
      case 'help': {
        const status = await getStatus()
        return formatRemoteHelp(cfg.remote, {
          sessionID,
          sessionTitle: status.sessionTitle,
        })
      }
      case 'status': {
        const status = await getStatus()
        return [
          `Email-bound session: ${status.sessionID || '(none)'}`,
          `Title: ${status.sessionTitle || '(untitled)'}`,
          `Directory: ${status.sessionDirectory || '(unknown)'}`,
          `Project: ${status.sessionProjectID || '(none)'}`,
          `This thread's session: ${sessionID}`,
          `Established: ${status.established ? 'yes' : 'no'}`,
          `Verified: ${status.verified ? 'yes' : 'no'}`,
          `Permission decisions: ${cfg.remote.decisions ? 'on' : 'off'}`,
          `Multiple-choice answers: ${cfg.remote.questions ? 'on' : 'off'}`,
          `High-risk email approval: ${cfg.remote.highRiskDecisions ? 'on' : 'off'}`,
          `Session watch: ${cfg.remote.watch ? 'on' : 'off'}`,
          `Read receipts: ${cfg.remote.readReceipts === false ? 'off' : 'on'}`,
        ].join('\n')
      }
      case 'peek': {
        if (!cfg.remote.peek) return 'Session output by email is disabled in the GUI.'
        let target = sessionID
        let limit = 5
        for (const token of [command.argument, command.rest].filter(Boolean)) {
          if (/^\d+$/.test(token)) limit = Number(token)
          else {
            const match = resolveSessionRef(catalog.sessions, token)
            if (!match) throw new Error(`Unknown session "${token}"; use !sessions to list sessions`)
            target = match.id
          }
        }
        return formatPeek(await ctx.session.context({ sessionID: target }), limit)
      }
      case 'tail': {
        if (!cfg.remote.tail) return 'Terminal tail by email is disabled in the GUI.'
        if (!ctx.experimental?.terminal?.read) return 'This OpenCode version does not expose a terminal tail to plugins.'
        const tokens = [command.argument, command.rest].filter(Boolean)
        const lineToken = tokens.find((token) => /^\d+$/.test(token))
        const lines = Math.max(1, Math.min(Number(lineToken) || 80, 500))
        const result = await ctx.experimental.terminal.read({ sessionID, lines })
        const text = typeof result === 'string'
          ? result
          : String(result?.text || result?.output || JSON.stringify(result || ''))
        return text.trim().slice(-12_000) || `No terminal output for session ${sessionID}.`
      }
      case 'send': {
        if (!cfg.remote.sendFiles) return 'Sending project files by email is disabled in the GUI.'
        const filePath = [command.argument, command.rest].filter(Boolean).join(' ').trim()
        if (!filePath) return 'Usage: !send <project-file>'
        const result = await sendFile({ sessionID, filePath, text: 'Attached on request.' })
        return result.content
      }
      case 'watch': {
        if (!cfg.remote.watch) return 'Session watch is disabled in the GUI.'
        let target = sessionID
        if (command.argument) {
          const match = resolveSessionRef(catalog.sessions, command.argument)
          if (!match) throw new Error(`Unknown session "${command.argument}"; use !sessions to list sessions`)
          target = match.id
        }
        state.data.watches[from] = {
          sessionID: target,
          inReplyTo: message.messageId,
          subject: message.subject,
          at: Date.now(),
        }
        await state.save()
        return `Watching session ${target}. You will get an encrypted mail when it finishes, fails or asks for a decision. Use !unwatch to stop.`
      }
      case 'unwatch': {
        delete state.data.watches[from]
        await state.save()
        return 'Session watch is off for this contact.'
      }
      default:
        return `${resolution.note || `Using session ${sessionID}`}.\n\nFurther replies in this subject stay in this session.`
    }
  }

  const LOCAL_ONLY_COMMANDS = new Set([
    'sessions', 'help', 'status', 'new', 'default',
    'peek', 'tail', 'send', 'watch', 'unwatch',
  ])
  const DECISION_COMMANDS = new Set(['approve', 'deny'])

  async function handle(raw) {
    try {
      if (await handleSecureJoinRequestPubkey(raw)) return
    } catch (error) {
      log(`SecureJoin request failed: ${error.message}`)
    }
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
    if (cfg.remote.mode === 'securejoin' && state.data.handshake.secureJoin?.verified && !message.encrypted) {
      log(`Ignoring plaintext from ${from}: encrypted-only mode is active after SecureJoin`)
      return
    }
    try {
      if (await handleSecureJoinRequestWithAuth(from, message)) return
    } catch (error) {
      log(`SecureJoin confirmation failed: ${error.message}`)
    }
    if (seenBefore(message.messageId)) return
    await markSeen(message.messageId)

    if (message.mdn) {
      await handleReadReceipt(from, message.mdn)
      return
    }

    const command = parseSessionCommand(message.text)
    const { establishedNow } = await learnPeer(from, message.autocrypt)
    if (message.wantsReceipt) {
      try {
        await sendReadReceipt(from, message.messageId)
      } catch (error) {
        log(`Could not send read receipt: ${error.message}`)
      }
    }
    if (command && DECISION_COMMANDS.has(command.command)) {
      await answerDecision(from, message, command)
      return
    }
    if (command?.command === 'answer') {
      await answerQuestion(from, message, command)
      return
    }
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
        await maybeSendWelcome(from, message, sessionID)
      } catch (error) {
        log(`Could not send welcome mail: ${error.message}`)
      }
    }

    if (command && LOCAL_ONLY_COMMANDS.has(command.command)) {
      const catalog = await listSessions()
      const text = await localCommandReply(from, message, command, catalog, sessionID, resolution)
      await sendCommandReply(from, message, sessionID, text)
      return
    }
    if (command?.command === 'use' && !command.rest) {
      await sendCommandReply(from, message, sessionID, `${resolution.note || `Using session ${sessionID}`}.\n\nFurther replies in this subject stay in this session.`)
      return
    }
    if (command?.command === 'use') {
      // `!use <id> question` switches the thread and asks in one email.
      command.rest = `${resolution.note || `Using session ${sessionID}`}\n\n${command.rest}`
    }

    await enqueue(sessionID, async () => {
      const current = sessionStatus.get(sessionID)
      const wasBusy = inFlight.has(sessionID) || current === 'busy' || current === 'retry'
      inFlight.add(sessionID)
      try {
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
          delivery: wasBusy ? 'queue' : 'steer',
          metadata: { source: 'autocrypt-email', from, messageId: message.messageId, sessionID },
        })
        if (wasBusy) {
          await sendCommandReply(from, message, sessionID, `Session ${sessionID} is busy; your prompt was queued. !watch ${sessionID} emails you when it finishes.`)
          return
        }
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
      } finally {
        inFlight.delete(sessionID)
      }
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
      startEvents()
      void startImap(cfg, store, handle, controller.signal, log)
      if (cfg.remote.mode === 'autocrypt' && cfg.pinned.contact && !state.data.peers[cfg.pinned.contact]?.keydata) {
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
    processEvent: handleEvent,
    confirmQuestionReply,
    getStatus,
    getSecureJoinQr,
    async startHandshake() {
      if (cfg.remote.mode !== 'autocrypt') {
        throw new Error('Autocrypt request is only available in Autocrypt remote mode')
      }
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
