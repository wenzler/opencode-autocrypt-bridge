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
  remoteMode: { type: 'string', enum: ['securejoin', 'autocrypt'] },
  secureJoinAuth: { type: 'string' },
  secureJoinName: { type: 'string' },
  secureJoinVersion: { type: 'string' },
  secureJoinRelays: { type: 'string' },
  secureJoinInviteNumber: { type: 'string' },
  requireEncrypted: { type: 'boolean' },
  pollIntervalMs: { type: 'number' },
  verifyCertificate: { type: 'boolean' },
  deleteAfterRead: { type: 'boolean' },
  privateKeyArmored: { type: 'string' },
  keyPassphrase: { type: 'string' },
  generateKey: { type: 'boolean' },
  preferEncryptMutual: { type: 'boolean' },
  emailDecisions: { type: 'boolean' },
  emailHighRiskDecisions: { type: 'boolean' },
  emailQuestions: { type: 'boolean' },
  emailPeek: { type: 'boolean' },
  emailTail: { type: 'boolean' },
  emailSendFiles: { type: 'boolean' },
  emailWatch: { type: 'boolean' },
  emailReadReceipts: { type: 'boolean' },
  emailProgress: { type: 'boolean' },
  emailProgressIntervalMs: { type: 'number' },
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
    hasSecureJoinAuth: { type: 'boolean' },
    hasPrivateKey: { type: 'boolean' },
    hasKeyPassphrase: { type: 'boolean' },
  },
  additionalProperties: false,
}

const statusOutput = {
  type: 'object',
  properties: {
    pluginVersion: { type: 'string' },
    running: { type: 'boolean' },
    configured: { type: 'boolean' },
    remoteMode: { type: 'string', enum: ['securejoin', 'autocrypt'] },
    emailDisabled: { type: 'boolean' },
    address: { type: 'string' },
    selfFingerprint: { type: 'string' },
    pinnedContact: { type: 'string' },
    pinnedFingerprint: { type: 'string' },
    learnedFingerprint: { type: 'string' },
    established: { type: 'boolean' },
    verified: { type: 'boolean' },
    handshake: { type: 'string' },
    secureJoin: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        address: { type: 'string' },
        fingerprint: { type: 'string' },
        hasAuth: { type: 'boolean' },
        name: { type: 'string' },
        version: { type: 'string' },
        createdAt: { type: 'number' },
      },
      additionalProperties: false,
    },
    lastError: { type: 'string' },
    sessionID: { type: 'string' },
    sessionTitle: { type: 'string' },
    sessionDirectory: { type: 'string' },
    sessionProjectID: { type: 'string' },
    lastReceiptAt: { type: 'number' },
    queuedReplies: { type: 'number' },
    nextReplyRetryAt: { type: 'number' },
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
    emailDisabled: { type: 'boolean' },
  },
  additionalProperties: false,
}

const questionFieldSchema = {
  type: 'object',
  properties: {
    key: { type: 'string' },
    title: { type: 'string' },
    description: { type: 'string' },
    type: { type: 'string' },
    options: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          value: { type: 'string' },
          label: { type: 'string' },
          description: { type: 'string' },
        },
        additionalProperties: false,
      },
    },
  },
  additionalProperties: false,
}

const questionEvent = {
  type: 'object',
  properties: {
    formID: { type: 'string' },
    code: { type: 'string' },
    sessionID: { type: 'string' },
    title: { type: 'string' },
    fields: { type: 'array', items: questionFieldSchema },
  },
  additionalProperties: false,
}

const answerValueSchema = {
  anyOf: [
    { type: 'string' },
    { type: 'number' },
    { type: 'boolean' },
    { type: 'array', items: { type: 'string' } },
  ],
}

const questionAnswerEvent = {
  type: 'object',
  properties: {
    formID: { type: 'string' },
    sessionID: { type: 'string' },
    answer: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          key: { type: 'string' },
          value: answerValueSchema,
        },
        additionalProperties: false,
      },
    },
  },
  additionalProperties: false,
}

const ackOutput = {
  type: 'object',
  properties: { accepted: { type: 'boolean' } },
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
          auth: { type: 'string' },
          inviteNumber: { type: 'string' },
          relays: { type: 'string' },
        },
        additionalProperties: false,
      },
    },
    testMailAccount: {
      input: {
        type: 'object',
        properties: settingsProperties,
        additionalProperties: false,
      },
      output: {
        type: 'object',
        properties: {
          imap: { type: 'boolean' },
          smtp: { type: 'boolean' },
          errors: { type: 'array', items: { type: 'string' } },
        },
        additionalProperties: false,
      },
    },
    startSecureJoin: {
      input: emptyInput,
      output: statusOutput,
    },
    cancelSecureJoin: {
      input: emptyInput,
      output: statusOutput,
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
    reportQuestionReply: {
      input: {
        type: 'object',
        properties: {
          formID: { type: 'string' },
          ok: { type: 'boolean' },
          error: { type: 'string' },
        },
        required: ['formID', 'ok'],
        additionalProperties: false,
      },
      output: ackOutput,
    },
  },
  events: {
    status: {
      schema: statusOutput,
    },
    question: {
      schema: questionEvent,
    },
    questionAnswer: {
      schema: questionAnswerEvent,
    },
  },
})
