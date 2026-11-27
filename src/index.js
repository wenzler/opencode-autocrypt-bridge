import { Plugin } from '@opencode/plugin'
import { createBridge } from './bridge.js'
import { loadConfig, loadMailConfig } from './config.js'
import { parseInviteUrl } from './headers.js'
import { testMailAccount as testMailAccountTransport } from './mail.js'
import { BridgeRpc } from './rpc.js'
import { formatSessionDirectory } from './session.js'
import { applySettingValues, settingsView, storedSettings } from './settings.js'

const PLUGIN_VERSION = '0.5.35'
const STORAGE_KEY = 'autocrypt.settings'
const RUNTIME_KEY = Symbol.for('opencode-autocrypt-bridge.runtime')

/**
 * OpenCode can load a plugin more than once (hot reload / GUI attach), and an
 * older RPC registration can keep answering calls after a newer load. All RPC
 * and tool handlers therefore read the one current runtime from this global
 * slot instead of closing over the runtime of their own plugin load.
 */
function runtimeSlot() {
  if (!globalThis[RUNTIME_KEY]) {
    globalThis[RUNTIME_KEY] = { token: null, stop: null, runtime: null }
  }
  return globalThis[RUNTIME_KEY]
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
  if (previousStop) await previousStop()

  const runtime = {
    ctx,
    options: ctx.options || {},
    optionValues: storedSettings(ctx.options || {}),
    stored: storedSettings(await ctx.storage.get(STORAGE_KEY)),
    cfg: null,
    bridge: null,
    registration: null,
    configError: '',
  }
  slot.runtime = runtime

  const statusView = (status, current = slot.runtime) => ({
    pluginVersion: PLUGIN_VERSION,
    running: false,
    remoteMode: 'securejoin',
    emailDisabled: false,
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
    configured: Boolean(current?.cfg),
  })

  const visibleValues = (current = slot.runtime) => ({ ...current.optionValues, ...current.stored })

  const unconfiguredStatus = (current = slot.runtime) => {
    const view = settingsView(visibleValues(current))
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
      lastError: current.configError || 'Finish setup in Settings → Autocrypt Bridge',
    }, current)
  }

  // Bridge status callbacks call emit(status); RPC notifications call
  // emit(name, payload). Both go through the current registration.
  const emit = (name, data) => {
    const current = slot.runtime
    if (!current?.registration) return
    const eventName = typeof name === 'string' ? name : 'status'
    const payload = typeof name === 'string' ? data : statusView(name, current)
    if (!payload) return
    void current.registration.events.emit(eventName, payload).catch(() => {})
  }

  const currentStatus = async () => {
    const current = slot.runtime
    if (!current) return statusView({ lastError: 'Autocrypt Bridge is not loaded' })
    return current.bridge
      ? statusView(await current.bridge.getStatus(), current)
      : unconfiguredStatus(current)
  }

  /** Start the bridge when settings are complete; otherwise stay UI-configurable. */
  const stopBridge = async () => {
    const current = slot.runtime
    const bridge = current?.bridge
    if (current) current.bridge = null
    if (slot.stop === stopBridge) slot.stop = null
    if (bridge) await bridge.stop()
  }

  /**
   * Rebuild the mail bridge from stored settings. Setup calls this guarded so
   * an older async load cannot overwrite a newer one; RPC calls are unguarded
   * so even a stale registration can restart the current runtime.
   */
  const restart = async (guarded = false) => {
    const current = slot.runtime
    if (!current) return currentStatus()
    if (guarded && (slot.token !== token || slot.runtime !== current)) {
      // A newer load owns the slot. Let it (or the next guarded restart) start
      // the bridge instead of leaving the current runtime unconfigured.
      return restart(false)
    }
    await stopBridge()
    current.stored = storedSettings(await current.ctx.storage.get(STORAGE_KEY))
    if (guarded && (slot.token !== token || slot.runtime !== current)) return restart(false)
    try {
      current.cfg = loadConfig({ ...current.options, ...current.stored }, process.env)
      current.configError = ''
      current.bridge = await createBridge(current.ctx, current.cfg, {
        onStatus: emit,
        onQuestion: (question) => emit('question', question),
        onQuestionAnswer: (answer) => emit('questionAnswer', answer),
      })
      if (guarded && (slot.token !== token || slot.runtime !== current)) {
        const staleBridge = current.bridge
        current.bridge = null
        if (staleBridge) await staleBridge.stop()
        return restart(false)
      }
      await current.bridge.start()
      if (guarded && (slot.token !== token || slot.runtime !== current)) {
        const staleBridge = current.bridge
        current.bridge = null
        if (staleBridge) await staleBridge.stop()
        return restart(false)
      }
      slot.stop = stopBridge
    } catch (error) {
      current.cfg = null
      current.configError = error.message
      emit(unconfiguredStatus(current))
    }
    return currentStatus()
  }

  runtime.registration = await ctx.rpc.register(BridgeRpc, {
    getSettings: async () => settingsView(visibleValues()),
    updateSettings: async (input) => {
      const current = slot.runtime
      const values = applySettingValues(current.stored, input)
      // Incomplete settings are allowed to persist so the GUI can be filled
      // in stages. loadConfig() in restart() is the hard gate: no bridge is
      // created until the pinned contact and transport are valid.
      await current.ctx.storage.set(STORAGE_KEY, values)
      current.stored = values
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
    testMailAccount: async (input = {}) => {
      const current = slot.runtime
      // Reuse the same merge rules as a settings save: blank secret inputs and
      // the redacted invite URL keep their effective values.
      const merged = applySettingValues(visibleValues(current), input || {})
      return testMailAccountTransport(loadMailConfig(merged, process.env))
    },
    startSecureJoin: async () => {
      if (!slot.runtime?.bridge) throw new Error('Autocrypt Bridge is not configured')
      return slot.runtime.bridge.startSecureJoin()
    },
    cancelSecureJoin: async () => {
      if (!slot.runtime?.bridge) throw new Error('Autocrypt Bridge is not configured')
      return slot.runtime.bridge.cancelSecureJoin()
    },
    startHandshake: async () => {
      if (!slot.runtime?.bridge) throw new Error('Autocrypt Bridge is not configured')
      return slot.runtime.bridge.startHandshake()
    },
    rescanInbox: async () => {
      if (!slot.runtime?.bridge) throw new Error('Autocrypt Bridge is not configured')
      return slot.runtime.bridge.rescanInbox()
    },
    resetContact: async () => {
      if (!slot.runtime?.bridge) throw new Error('Autocrypt Bridge is not configured')
      return slot.runtime.bridge.resetContact()
    },
    listSessions: async () => (slot.runtime?.bridge
      ? slot.runtime.bridge.listSessions()
      : { sessions: [], projects: [], boundSessionID: '', emailDisabled: false }),
    bindSession: async (input) => {
      if (!slot.runtime?.bridge) throw new Error('Autocrypt Bridge is not configured')
      return slot.runtime.bridge.bindSession(input.sessionID)
    },
    createSession: async (input) => {
      if (!slot.runtime?.bridge) throw new Error('Autocrypt Bridge is not configured')
      const result = await slot.runtime.bridge.createAndBindSession(input.title, input.directory)
      return result.status
    },
    reportQuestionReply: async (input) => {
      if (!slot.runtime?.bridge) throw new Error('Autocrypt Bridge is not configured')
      await slot.runtime.bridge.confirmQuestionReply({
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
        if (!slot.runtime?.bridge) return { content: 'The Autocrypt bridge is not configured' }
        return slot.runtime.bridge.sendFile({
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
        if (!slot.runtime?.bridge) return { content: 'The Autocrypt bridge is not configured' }
        const catalog = await slot.runtime.bridge.listSessions()
        return { content: formatSessionDirectory(catalog, catalog.boundSessionID, catalog.emailDisabled) }
      },
    })
  })

  await restart(true)

  let disposed = false
  const dispose = async () => {
    if (disposed) return
    disposed = true
    // A superseded plugin load must not tear down the newer runtime or its
    // registrations; stale handlers now delegate to slot.runtime anyway.
    if (slot.runtime !== runtime || slot.token !== token) return
    await stopBridge()
    await tool.dispose()
    await runtime.registration.dispose()
    slot.token = null
    if (slot.stop === stopBridge) slot.stop = null
    slot.runtime = null
  }
  return dispose
}
