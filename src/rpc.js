import { Rpc } from '@opencode/plugin/rpc'

const settingsProperties = {
  address: { type: 'string' },
  displayName: { type: 'string' },
  imapHost: { type: 'string' },
  imapPort: { type: 'number' },
  imapSecurity: { type: 'string', enum: ['tls', 'starttls', 'plain'] },
  imapUser: { type: 'string' },
  imapPassword: { type: 'string' },
  imapMailbox: { type: 'string' },
  smtpHost: { type: 'string' },
  smtpPort: { type: 'number' },
  smtpSecurity: { type: 'string', enum: ['tls', 'starttls', 'plain'] },
  smtpUser: { type: 'string' },
  smtpPassword: { type: 'string' },
  pinnedContact: { type: 'string' },
  pinnedFingerprint: { type: 'string' },
  pinnedContactKey: { type: 'string' },
  inviteUrl: { type: 'string' },
  requireEncrypted: { type: 'boolean' },
  pollIntervalMs: { type: 'number' },
  verifyCertificate: { type: 'boolean' },
  privateKeyArmored: { type: 'string' },
  keyPassphrase: { type: 'string' },
  generateKey: { type: 'boolean' },
  preferEncryptMutual: { type: 'boolean' },
  defaultSessionID: { type: 'string' },
  defaultSessionDirectory: { type: 'string' },
}

const emptyInput = {
  type: 'object',
  properties: {},
  additionalProperties: false,
}

const settingsOutput = {
  type: 'object',
  properties: {
    ...settingsProperties,
    hasImapPassword: { type: 'boolean' },
    hasSmtpPassword: { type: 'boolean' },
    hasPinnedContactKey: { type: 'boolean' },
    hasPrivateKey: { type: 'boolean' },
    hasKeyPassphrase: { type: 'boolean' },
  },
  additionalProperties: false,
}

const statusOutput = {
  type: 'object',
  properties: {
    running: { type: 'boolean' },
    configured: { type: 'boolean' },
    address: { type: 'string' },
    pinnedContact: { type: 'string' },
    pinnedFingerprint: { type: 'string' },
    learnedFingerprint: { type: 'string' },
    established: { type: 'boolean' },
    verified: { type: 'boolean' },
    handshake: { type: 'string' },
    lastError: { type: 'string' },
    sessionID: { type: 'string' },
    sessionTitle: { type: 'string' },
    sessionDirectory: { type: 'string' },
    sessionProjectID: { type: 'string' },
  },
  additionalProperties: false,
}

const sessionInfo = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    title: { type: 'string' },
    projectID: { type: 'string' },
    directory: { type: 'string' },
    agent: { type: 'string' },
    model: { type: 'string' },
    updated: { type: 'number' },
  },
  additionalProperties: false,
}

const projectInfo = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    directory: { type: 'string' },
    sessionCount: { type: 'number' },
    updated: { type: 'number' },
  },
  additionalProperties: false,
}

const sessionsOutput = {
  type: 'object',
  properties: {
    sessions: { type: 'array', items: sessionInfo },
    projects: { type: 'array', items: projectInfo },
    boundSessionID: { type: 'string' },
    defaultSessionID: { type: 'string' },
  },
  additionalProperties: false,
}

export const BridgeRpc = Rpc.define({
  id: 'autocrypt-bridge',
  methods: {
    getSettings: {
      input: emptyInput,
      output: settingsOutput,
    },
    updateSettings: {
      input: {
        type: 'object',
        properties: settingsProperties,
        additionalProperties: false,
      },
      output: statusOutput,
    },
    getStatus: {
      input: emptyInput,
      output: statusOutput,
    },
    parseInvite: {
      input: {
        type: 'object',
        properties: { invite: { type: 'string' } },
        required: ['invite'],
        additionalProperties: false,
      },
      output: {
        type: 'object',
        properties: {
          fingerprint: { type: 'string' },
          address: { type: 'string' },
          name: { type: 'string' },
          version: { type: 'string' },
        },
        additionalProperties: false,
      },
    },
    startHandshake: {
      input: emptyInput,
      output: statusOutput,
    },
    rescanInbox: {
      input: emptyInput,
      output: statusOutput,
    },
    resetContact: {
      input: emptyInput,
      output: statusOutput,
    },
    listSessions: {
      input: emptyInput,
      output: sessionsOutput,
    },
    bindSession: {
      input: {
        type: 'object',
        properties: { sessionID: { type: 'string' } },
        required: ['sessionID'],
        additionalProperties: false,
      },
      output: statusOutput,
    },
    createSession: {
      input: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          directory: { type: 'string' },
        },
        additionalProperties: false,
      },
      output: statusOutput,
    },
  },
  events: {
    status: {
      schema: statusOutput,
    },
  },
})
