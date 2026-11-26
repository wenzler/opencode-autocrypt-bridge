import { Plugin } from '@opencode/plugin'
import { createBridge } from './bridge.js'
import { loadConfig, normalizeHost } from './config.js'
import { parseInviteUrl, redactInviteUrl } from './headers.js'
import { BridgeRpc } from './rpc.js'
import { formatSessionDirectory } from './session.js'

const SETTING_KEYS = [
  'address', 'displayName', 'imapHost', 'imapPort', 'imapSecurity', 'imapUser', 'imapPassword', 'imapMailbox',
  'smtpHost', 'smtpPort', 'smtpSecurity', 'smtpUser', 'smtpPassword', 'pinnedContact',
  'pinnedFingerprint', 'pinnedContactKey', 'inviteUrl', 'remoteMode',
  'secureJoinAuth', 'secureJoinName', 'secureJoinVersion', 'secureJoinRelays', 'secureJoinInviteNumber',
  'requireEncrypted',
  'pollIntervalMs', 'verifyCertificate', 'deleteAfterRead', 'privateKeyArmored', 'keyPassphrase', 'generateKey', 'preferEncryptMutual',
  'emailDecisions', 'emailHighRiskDecisions', 'emailQuestions',
  'emailPeek', 'emailTail', 'emailSendFiles', 'emailWatch', 'emailReadReceipts',
]

const SECRET_KEYS = new Set([
  'imapPassword', 'smtpPassword', 'privateKeyArmored', 'keyPassphrase', 'secureJoinAuth',
])
const HOST_KEYS = new Set(['imapHost', 'smtpHost'])
const UI_DEFAULTS = {
  remoteMode: 'securejoin',
  secureJoinVersion: '3',
  verifyCertificate: true,
  deleteAfterRead: false,
  generateKey: true,
  preferEncryptMutual: true,
  emailDecisions: true,
  emailHighRiskDecisions: false,
  emailQuestions: true,
  emailPeek: true,
  emailTail: true,
  emailSendFiles: true,
  emailWatch: true,
  emailReadReceipts: true,
}
const STORAGE_KEY = 'autocrypt.settings'
const RUNTIME_KEY = Symbol.for('opencode-autocrypt-bridge.runtime')

/**
 * OpenCode can load a plugin more than once (hot reload / GUI attach). Keep one
 * mail bridge per process, but leave each load's RPC/tool registration alone so
 * a reload never makes the bridge RPC unavailable.
 */
function runtimeSlot() {
  if (!globalThis[RUNTIME_KEY]) {
    globalThis[RUNTIME_KEY] = { token: null, stop: null }
  }
  return globalThis[RUNTIME_KEY]
}

function storedSettings(stored) {
  const result = {}
  if (!stored || typeof stored !== 'object') return result
  for (const key of SETTING_KEYS) {
    if (stored[key] === undefined || stored[key] === null || stored[key] === '') continue
    result[key] = stored[key]
  }
  return result
}

/**
 * Build the GUI/RPC view from raw flat settings. This must work before the
 * bridge is configured, so it does not go through loadConfig().
 */
function settingsView(values) {
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

export default Plugin.define({
  id: 'autocrypt-bridge',
  async setup(ctx) {
    return setupInstance(ctx, runtimeSlot())
  },
})

async function setupInstance(ctx, slot) {
  const token = {}
  const previousStop = slot.stop
  slot.token = token
  slot.stop = null
  if (previousStop) previousStop()
  const options = ctx.options || {}
    const optionValues = storedSettings(options)
    let stored = storedSettings(await ctx.storage.get(STORAGE_KEY))
    const runtime = { cfg: null, bridge: null, registration: null, configError: '' }

    const configFrom = (values) => loadConfig({ ...options, ...values }, process.env)

    const statusView = (status) => ({
      running: false,
      remoteMode: 'securejoin',
      address: '',
      selfFingerprint: '',
      pinnedContact: '',
      pinnedFingerprint: '',
      learnedFingerprint: '',
      established: false,
      verified: false,
      handshake: 'idle',
      secureJoin: {
        status: 'idle', address: '', fingerprint: '', hasAuth: false, name: '', version: '3', createdAt: 0,
      },
      lastError: '',
      sessionID: '',
      sessionTitle: '',
      sessionDirectory: '',
      sessionProjectID: '',
      ...status,
      configured: Boolean(runtime.cfg),
    })

    const visibleValues = () => ({ ...optionValues, ...stored })

    const unconfiguredStatus = () => {
      const view = settingsView(visibleValues())
      return statusView({
        address: view.address,
        pinnedContact: view.pinnedContact,
        pinnedFingerprint: view.pinnedFingerprint,
        secureJoin: {
          status: 'unconfigured',
          address: view.pinnedContact,
          fingerprint: view.pinnedFingerprint,
          hasAuth: Boolean(view.hasSecureJoinAuth),
          name: view.secureJoinName,
          version: view.secureJoinVersion || '3',
          createdAt: 0,
        },
        handshake: 'unconfigured',
        lastError: runtime.configError || 'Finish setup in Settings → Autocrypt Bridge',
      })
    }

    // Bridge status callbacks call emit(status); RPC notifications call
    // emit(name, payload). Both go through the same registration.
    const emit = (name, data) => {
      if (!runtime.registration) return
      const eventName = typeof name === 'string' ? name : 'status'
      const payload = typeof name === 'string' ? data : statusView(name)
      if (!payload) return
      void runtime.registration.events.emit(eventName, payload).catch(() => {})
    }

    const currentStatus = async () => (
      runtime.bridge ? statusView(await runtime.bridge.getStatus()) : unconfiguredStatus()
    )

    /** Start the bridge when settings are complete; otherwise stay UI-configurable. */
    const stopBridge = () => {
      runtime.bridge?.stop()
      runtime.bridge = null
      if (slot.stop === stopBridge) slot.stop = null
    }

    const restart = async () => {
      stopBridge()
      stored = storedSettings(await ctx.storage.get(STORAGE_KEY))
      if (slot.token !== token) return currentStatus()
      try {
        runtime.cfg = configFrom(stored)
        runtime.configError = ''
        runtime.bridge = await createBridge(ctx, runtime.cfg, {
          onStatus: emit,
          onQuestion: (question) => emit('question', question),
          onQuestionAnswer: (answer) => emit('questionAnswer', answer),
        })
        if (slot.token !== token) {
          runtime.bridge.stop()
          runtime.bridge = null
          return currentStatus()
        }
        runtime.bridge.start()
        slot.stop = stopBridge
      } catch (error) {
        runtime.cfg = null
        runtime.configError = error.message
        emit(unconfiguredStatus())
      }
      return currentStatus()
    }

    runtime.registration = await ctx.rpc.register(BridgeRpc, {
      getSettings: async () => settingsView(visibleValues()),
      updateSettings: async (input) => {
        const values = { ...stored }
        const previousInvite = String(stored.inviteUrl || '')
        const previousRedacted = redactInviteUrl(previousInvite)
        for (const key of SETTING_KEYS) {
          const value = input[key]
          if (value === undefined || value === null) continue
          // Blank secret fields keep the stored value. The redacted invite URL
          // shown in the GUI also keeps the stored auth code on a plain save.
          if (SECRET_KEYS.has(key) && value === '') continue
          if (key === 'inviteUrl' && previousInvite && value === previousRedacted) continue
          let storedValue = value
          if (HOST_KEYS.has(key)) storedValue = normalizeHost(value)
          if (storedValue === '') delete values[key]
          else values[key] = storedValue
        }
        // Incomplete settings are allowed to persist so the GUI can be filled
        // in stages. loadConfig() in restart() is the hard gate: no bridge is
        // created until the pinned contact and transport are valid.
        await ctx.storage.set(STORAGE_KEY, values)
        stored = values
        return restart()
      },
      getStatus: currentStatus,
      parseInvite: async (input) => {
        const invite = parseInviteUrl(input.invite)
        if (!invite) throw new Error('Empty invite URL')
        return {
          fingerprint: invite.fingerprint,
          address: invite.address,
          name: invite.name,
          version: invite.version,
          auth: invite.auth,
          inviteNumber: invite.inviteNumber,
          relays: invite.relays,
        }
      },
      startSecureJoin: async () => {
        if (!runtime.bridge) throw new Error('Autocrypt Bridge is not configured')
        return runtime.bridge.startSecureJoin()
      },
      startHandshake: async () => {
        if (!runtime.bridge) throw new Error('Autocrypt Bridge is not configured')
        return runtime.bridge.startHandshake()
      },
      rescanInbox: async () => {
        if (!runtime.bridge) throw new Error('Autocrypt Bridge is not configured')
        return runtime.bridge.rescanInbox()
      },
      resetContact: async () => {
        if (!runtime.bridge) throw new Error('Autocrypt Bridge is not configured')
        return runtime.bridge.resetContact()
      },
      listSessions: async () => (runtime.bridge
        ? runtime.bridge.listSessions()
        : { sessions: [], projects: [], boundSessionID: '' }),
      bindSession: async (input) => {
        if (!runtime.bridge) throw new Error('Autocrypt Bridge is not configured')
        return runtime.bridge.bindSession(input.sessionID)
      },
      createSession: async (input) => {
        if (!runtime.bridge) throw new Error('Autocrypt Bridge is not configured')
        const result = await runtime.bridge.createAndBindSession(input.title, input.directory)
        return result.status
      },
      reportQuestionReply: async (input) => {
        if (!runtime.bridge) throw new Error('Autocrypt Bridge is not configured')
        await runtime.bridge.confirmQuestionReply({
          formID: input.formID,
          ok: Boolean(input.ok),
          error: String(input.error || ''),
        })
        return { accepted: true }
      },
    })

    const tool = await ctx.tool.transform((editor) => {
      editor.add({
        name: 'autocrypt_send_file',
        description: 'Send a file from the current project as an OpenPGP/MIME attachment to this session’s email contact.',
        input: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'Project-relative or absolute file path' },
            text: { type: 'string', description: 'Optional caption' },
          },
          required: ['path'],
          additionalProperties: false,
        },
        execute: async (input, context) => {
          if (!runtime.bridge) return { content: 'The Autocrypt bridge is not configured' }
          return runtime.bridge.sendFile({
            sessionID: context.sessionID,
            filePath: input.path,
            text: input.text,
          })
        },
      })
      editor.add({
        name: 'autocrypt_sessions',
        description: 'List open OpenCode projects and sessions when an email asks which session or project is active.',
        input: { type: 'object', properties: {}, additionalProperties: false },
        execute: async () => {
          if (!runtime.bridge) return { content: 'The Autocrypt bridge is not configured' }
          const catalog = await runtime.bridge.listSessions()
          return { content: formatSessionDirectory(catalog, catalog.boundSessionID) }
        },
      })
    })

    await restart()

  let disposed = false
  const dispose = async () => {
    if (disposed) return
    disposed = true
    stopBridge()
    await tool.dispose()
    await runtime.registration.dispose()
    if (slot.token === token) {
      slot.token = null
      if (slot.stop === stopBridge) slot.stop = null
    }
  }
  return dispose
}
