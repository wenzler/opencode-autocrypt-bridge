import { Plugin } from '@opencode/plugin'
import { createBridge } from './bridge.js'
import { loadConfig, normalizeHost } from './config.js'
import { parseInviteUrl, redactInviteUrl } from './headers.js'
import { BridgeRpc } from './rpc.js'
import { formatSessionDirectory } from './session.js'

const SETTING_KEYS = [
  'address', 'displayName', 'imapHost', 'imapPort', 'imapSecurity', 'imapUser', 'imapPassword', 'imapMailbox',
  'smtpHost', 'smtpPort', 'smtpSecurity', 'smtpUser', 'smtpPassword', 'pinnedContact',
  'pinnedFingerprint', 'pinnedContactKey', 'inviteUrl', 'requireEncrypted',
  'pollIntervalMs', 'verifyCertificate', 'privateKeyArmored', 'keyPassphrase', 'generateKey', 'preferEncryptMutual',
  'defaultSessionID', 'defaultSessionDirectory',
]

const SECRET_KEYS = new Set(['imapPassword', 'smtpPassword', 'privateKeyArmored', 'keyPassphrase'])
const HOST_KEYS = new Set(['imapHost', 'smtpHost'])
const UI_DEFAULTS = { verifyCertificate: true, generateKey: true, preferEncryptMutual: true }
const STORAGE_KEY = 'autocrypt.settings'

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
  for (const key of SECRET_KEYS) view[key] = ''
  // Invite tokens are never used or stored; only public prefill fields remain.
  view.inviteUrl = redactInviteUrl(view.inviteUrl)
  return view
}

export default Plugin.define({
  id: 'autocrypt-bridge',
  async setup(ctx) {
    const options = ctx.options || {}
    const optionValues = storedSettings(options)
    let stored = storedSettings(await ctx.storage.get(STORAGE_KEY))
    const runtime = { cfg: null, bridge: null, registration: null, configError: '' }

    const configFrom = (values) => loadConfig({ ...options, ...values }, process.env)

    const statusView = (status) => ({
      running: false,
      address: '',
      pinnedContact: '',
      pinnedFingerprint: '',
      learnedFingerprint: '',
      established: false,
      verified: false,
      handshake: 'idle',
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
        handshake: 'unconfigured',
        lastError: runtime.configError || 'Finish setup in Settings → Autocrypt Bridge',
      })
    }

    const emit = (status) => {
      if (!runtime.registration || !status) return
      void runtime.registration.events.emit('status', statusView(status)).catch(() => {})
    }

    const currentStatus = async () => (
      runtime.bridge ? statusView(await runtime.bridge.getStatus()) : unconfiguredStatus()
    )

    /** Start the bridge when settings are complete; otherwise stay UI-configurable. */
    const restart = async () => {
      runtime.bridge?.stop()
      runtime.bridge = null
      stored = storedSettings(await ctx.storage.get(STORAGE_KEY))
      try {
        runtime.cfg = configFrom(stored)
        runtime.configError = ''
        runtime.bridge = await createBridge(ctx, runtime.cfg, { onStatus: emit })
        runtime.bridge.start()
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
        if (values.inviteUrl) values.inviteUrl = redactInviteUrl(values.inviteUrl)
        for (const key of SETTING_KEYS) {
          const value = input[key]
          if (value === undefined || value === null) continue
          if (SECRET_KEYS.has(key) && value === '') continue
          // i=/s= tokens are ignored; persist only the redacted URL. Host
          // fields are hostnames, not URLs, even if a form injects a scheme.
          let storedValue = value
          if (key === 'inviteUrl' && value) storedValue = redactInviteUrl(value)
          else if (HOST_KEYS.has(key)) storedValue = normalizeHost(value)
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
        }
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
        : { sessions: [], projects: [], boundSessionID: '', defaultSessionID: '' }),
      bindSession: async (input) => {
        if (!runtime.bridge) throw new Error('Autocrypt Bridge is not configured')
        return runtime.bridge.bindSession(input.sessionID)
      },
      createSession: async (input) => {
        if (!runtime.bridge) throw new Error('Autocrypt Bridge is not configured')
        const result = await runtime.bridge.createAndBindSession(input.title, input.directory)
        return result.status
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

    return async () => {
      runtime.bridge?.stop()
      await tool.dispose()
      await runtime.registration.dispose()
    }
  },
})
