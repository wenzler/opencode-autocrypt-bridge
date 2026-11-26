import { createHash } from 'node:crypto'
import path from 'node:path'

/**
 * Command registry for the encrypted, IRC-style email remote.
 *
 * Nothing here executes a shell command. Commands either answer an OpenCode
 * permission request through ctx.permission.reply(), read OpenCode session
 * state, or expand into a normal ctx.session.prompt().
 */
export const COMMAND_SPECS = [
  {
    names: ['sessions', 'list', 'projects'],
    usage: '!sessions',
    description: 'list open projects and sessions',
    gate: 'always',
  },
  {
    names: ['use', 'session'],
    usage: '!use <session-id> [question]',
    description: 'switch this email thread and optionally prompt in one mail',
    gate: 'always',
  },
  {
    names: ['new', 'create'],
    usage: '!new <title> in <project>',
    description: 'create a session in a listed project',
    gate: 'always',
  },
  {
    names: ['default', 'reset'],
    usage: '!default',
    description: 'return this thread to the email-bound session',
    gate: 'always',
  },
  {
    names: ['status'],
    usage: '!status',
    description: 'show binding, encryption and remote-control state',
    gate: 'always',
  },
  {
    names: ['help', 'commands', 'shortcuts'],
    usage: '!help',
    description: 'show this command list (also !commands, !shortcuts)',
    gate: 'always',
  },
  {
    names: ['approve', 'decide'],
    usage: '!approve <code> once|always',
    description: 'answer a permission request that is stalling a session',
    gate: 'decisions',
  },
  {
    names: ['deny', 'reject'],
    usage: '!deny <code> [reason]',
    description: 'reject a permission request with optional feedback',
    gate: 'decisions',
  },
  {
    names: ['answer'],
    usage: '!answer <code> <choice>[,choice][;choice…]',
    description: 'answer a multiple-choice question that is stalling a session',
    gate: 'questions',
  },
  {
    names: ['peek', 'output'],
    usage: '!peek [session-id] [count]',
    description: 'read the latest assistant output from a session',
    gate: 'peek',
  },
  {
    names: ['tail'],
    usage: '!tail [lines]',
    description: 'read the session terminal tail',
    gate: 'tail',
  },
  {
    names: ['send'],
    usage: '!send <project-file>',
    description: 'attach a file from the project directory',
    gate: 'sendFiles',
  },
  {
    names: ['watch'],
    usage: '!watch [session-id]',
    description: 'email this thread when the session finishes or fails',
    gate: 'watch',
  },
  {
    names: ['unwatch'],
    usage: '!unwatch',
    description: 'stop session notifications on this thread',
    gate: 'watch',
  },
]

const GATE_LABELS = {
  decisions: 'Allow permission decisions by email',
  questions: 'Allow multiple-choice answers by email',
  peek: 'Allow session output by email',
  tail: 'Allow terminal tail by email',
  sendFiles: 'Allow sending project files',
  watch: 'Allow session watch subscriptions',
}

function enabled(remote, gate) {
  if (gate === 'always') return true
  return Boolean(remote?.[gate])
}

/** Short, phone-friendly code for a permission request. */
export function decisionCode(requestID) {
  const digest = createHash('sha256').update(String(requestID || '')).digest('hex')
  return `D-${digest.slice(0, 6).toUpperCase()}`
}

function isLocalPath(resource) {
  const value = String(resource || '').trim()
  if (!value) return true
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(value)) return false
  if (value.startsWith('~')) return false
  return true
}

function insideDirectory(resource, rootDirectory) {
  const root = path.resolve(String(rootDirectory || process.cwd()))
  const target = path.resolve(root, String(resource))
  return target === root || target.startsWith(`${root}${path.sep}`)
}

/**
 * Classify a permission request before it is offered to the phone.
 *
 * Out-of-sandbox file access is always HIGH. Shell-like actions are HIGH too:
 * the email bridge must never become a remote shell.
 */
export function classifyPermission(action, resources = [], rootDirectory = '') {
  const normalizedAction = String(action || '').trim().toLowerCase()
  const highActions = new Set([
    'shell', 'bash', 'execute', 'external_directory', 'install', 'task', 'subagent', 'delegate',
  ])
  const mediumActions = new Set(['write', 'edit', 'patch', 'apply_patch', 'multiedit'])
  const reasons = []
  let level = mediumActions.has(normalizedAction) ? 'medium' : 'low'

  if (highActions.has(normalizedAction)) {
    level = 'high'
    reasons.push(`action ${normalizedAction || 'unknown'}`)
  }
  for (const resource of resources || []) {
    if (!isLocalPath(resource)) {
      level = 'high'
      reasons.push(`non-local resource ${resource}`)
      continue
    }
    if (!insideDirectory(resource, rootDirectory)) {
      level = 'high'
      reasons.push(`outside project directory: ${resource}`)
    }
  }
  return { level, reasons }
}

export function formatRemoteHelp(remote = {}, details = {}) {
  const lines = ['Autocrypt remote commands (reply in this encrypted thread):', '']
  const active = []
  const inactive = []
  for (const spec of COMMAND_SPECS) {
    const line = `  ${spec.usage.padEnd(34)} ${spec.description}`
    if (enabled(remote, spec.gate)) active.push(line)
    else inactive.push(`  ${spec.usage.padEnd(34)} ${spec.description} [off: ${GATE_LABELS[spec.gate] || spec.gate}]`)
  }
  lines.push(...active)
  if (inactive.length) {
    lines.push('', 'Disabled here:')
    lines.push(...inactive)
  }
  lines.push('')
  lines.push('Routing: each subject carries [session:ses_…]; replies stay in that session.')
  if (details.sessionID) lines.push(`This thread: ${details.sessionID}${details.sessionTitle ? ` — ${details.sessionTitle}` : ''}`)
  lines.push(`Permission decisions by email: ${remote.decisions ? 'on' : 'off'}`)
  lines.push(`Multiple-choice answers by email: ${remote.questions ? 'on' : 'off'}`)
  lines.push(`High-risk decisions by email: ${remote.highRiskDecisions ? 'on' : 'off'} (out-of-project file access and shell-like actions are high risk)`)
  if (Array.isArray(details.commands) && details.commands.length) {
    lines.push('')
    lines.push(`OpenCode commands also available at the desk: ${details.commands.slice(0, 24).join(', ')}`)
  }
  return lines.join('\n')
}

export function formatDecisionRequest({ code, action, resources = [], risk, enabled = true, canAnswer, highRiskAllowed, options = [], sessionID }) {
  const lines = [
    'OpenCode is waiting for a permission decision.',
    '',
    `Code: ${code}`,
    `Session: ${sessionID || '(unknown)'}`,
    `Action: ${action || '(unknown)'}`,
    `Risk: ${risk.level.toUpperCase()}${risk.reasons.length ? ` — ${risk.reasons.join('; ')}` : ''}`,
  ]
  if (resources.length) {
    lines.push('')
    lines.push('Resources:')
    for (const resource of resources.slice(0, 12)) lines.push(`  ${resource}`)
    if (resources.length > 12) lines.push(`  …and ${resources.length - 12} more`)
  }
  lines.push('')
  if (!enabled) {
    lines.push('Permission decisions by email are disabled in Settings → Autocrypt Bridge → Remote controls.')
    lines.push('You can still answer this request at the desktop.')
  } else if (!canAnswer) {
    lines.push('This request is HIGH RISK and email approval is disabled.')
    lines.push(`Enable “High-risk decisions by email” in Settings → Autocrypt Bridge → Remote controls to answer it from here.`)
    lines.push('You can still answer it at the desktop.')
  } else {
    lines.push('Reply with one of:')
    lines.push(`  !approve ${code} once`)
    if (options.includes('always')) lines.push(`  !approve ${code} always`)
    lines.push(`  !deny ${code} [reason]`)
    if (risk.level === 'high') lines.push('')
    if (risk.level === 'high') lines.push('This is HIGH RISK: out-of-project access or a shell-like action.')
    if (highRiskAllowed) lines.push('High-risk email approval is enabled in the GUI.')
  }
  return lines.join('\n')
}

/** Render an OpenCode question form as a phone-friendly numbered menu. */
export function formatQuestionRequest({ code, title, fields = [], sessionID }) {
  const lines = [
    'OpenCode is waiting for your answer.',
    '',
    `Code: ${code}`,
    `Session: ${sessionID || '(unknown)'}`,
    `Question: ${title || 'Questions'}`,
  ]
  for (const [index, field] of (Array.isArray(fields) ? fields : []).entries()) {
    lines.push('', `${index + 1}. ${field?.title || field?.description || `Question ${index + 1}`}`)
    if (field?.description && field.description !== field.title) lines.push(`   ${field.description}`)
    const options = Array.isArray(field?.options) ? field.options : []
    for (const [optionIndex, option] of options.entries()) {
      const label = option?.label || option?.value || String(optionIndex + 1)
      const detail = option?.description ? ` — ${option.description}` : ''
      lines.push(`   ${optionIndex + 1}) ${label}${detail}`)
    }
    if (field?.type === 'multiselect') lines.push('   (choose several with commas)')
    else if (options.length) lines.push('   (choose one number)')
    else lines.push('   (reply with text)')
  }
  lines.push('')
  lines.push(`Reply: !answer ${code} 1`)
  lines.push('Separate answers to several questions with “;”, for example: !answer CODE 1;2,3')
  lines.push('The desktop stays open; answering here continues the same session.')
  return lines.join('\n')
}

/**
 * Convert numbered email choices into an OpenCode form answer map.
 *
 * OpenCode validates each answer against its field type: a single-choice
 * question (type "string", even when it offers options) needs a string, while
 * only type "multiselect" accepts an array. Number, integer and boolean fields
 * are coerced to their native types.
 */
export function parseQuestionAnswers(fields = [], text = '') {
  const raw = String(text || '').trim()
  if (!raw) return { error: 'No answer supplied. Use !answer <code> <choice>.' }
  const groups = raw.split(/[;|]/).map((part) => part.trim()).filter(Boolean)
  const answer = {}
  for (const [index, field] of (Array.isArray(fields) ? fields : []).entries()) {
    const key = String(field?.key || `q${index}`)
    const group = groups[Math.min(index, groups.length - 1)] || ''
    if (!group) continue
    const type = String(field?.type || 'string')
    const options = Array.isArray(field?.options) ? field.options : []

    if (type === 'multiselect') {
      const values = []
      for (const token of group.split(',').map((part) => part.trim()).filter(Boolean)) {
        const numeric = /^\d+$/.exec(token)
        let selected
        if (numeric) {
          selected = options[Number(numeric[0]) - 1]
          if (!selected) return { error: `Choice ${token} is not listed for question ${index + 1}.` }
        } else if (options.length) {
          const needle = token.toLowerCase()
          selected = options.find((option) => (
            String(option?.label || '').toLowerCase() === needle
            || String(option?.value || '').toLowerCase() === needle
          ))
          if (!selected) return { error: `Choice "${token}" is not listed for question ${index + 1}.` }
        } else {
          selected = { value: token }
        }
        values.push(String(selected.value ?? selected.label))
      }
      answer[key] = values
      continue
    }

    if (type === 'boolean') {
      const normalized = group.toLowerCase()
      if (['1', 'true', 'yes', 'y', 'on'].includes(normalized)) answer[key] = true
      else if (['0', 'false', 'no', 'n', 'off'].includes(normalized)) answer[key] = false
      else return { error: `Answer "true" or "false" for question ${index + 1}.` }
      continue
    }

    if (type === 'number' || type === 'integer') {
      const numeric = Number(group)
      if (!Number.isFinite(numeric)) return { error: `Question ${index + 1} needs a number.` }
      if (type === 'integer' && !Number.isInteger(numeric)) return { error: `Question ${index + 1} needs a whole number.` }
      answer[key] = numeric
      continue
    }

    if (!options.length) {
      answer[key] = group
      continue
    }
    const numeric = /^\d+$/.exec(group)
    let selected
    if (numeric) {
      selected = options[Number(numeric[0]) - 1]
      if (!selected) return { error: `Choice ${group} is not listed for question ${index + 1}.` }
    } else {
      const needle = group.toLowerCase()
      selected = options.find((option) => (
        String(option?.label || '').toLowerCase() === needle
        || String(option?.value || '').toLowerCase() === needle
      ))
      if (!selected) return { error: `Choice "${group}" is not listed for question ${index + 1}.` }
    }
    answer[key] = String(selected.value ?? selected.label)
  }
  if (!Object.keys(answer).length) return { error: 'No answer supplied. Use !answer <code> <choice>.' }
  return { answer }
}

/** Render a compact, phone-readable tail of session messages. */
export function formatPeek(messages = [], limit = 5) {
  const count = Math.max(1, Math.min(Number(limit) || 5, 20))
  const selected = (Array.isArray(messages) ? messages : []).slice(-count)
  if (!selected.length) return 'No session messages are available yet.'
  const lines = [`Last ${selected.length} message(s):`, '']
  for (const entry of selected) {
    const role = entry?.type === 'assistant' ? 'assistant' : entry?.type === 'user' ? 'you' : (entry?.type || 'event')
    const parts = Array.isArray(entry?.content) ? entry.content : []
    const text = parts
      .filter((part) => part?.type === 'text')
      .map((part) => String(part.text || '').trim())
      .filter(Boolean)
      .join(' ')
      .slice(0, 1200)
    const tools = parts
      .filter((part) => part?.type === 'tool')
      .map((part) => {
        const state = part.state || {}
        const name = state.tool || part.tool || part.name || 'tool'
        const input = JSON.stringify(state.input || part.input || {}).slice(0, 200)
        return `${name}(${input})`
      })
    const body = [text, ...tools].filter(Boolean).join(' · ') || '(no text)'
    lines.push(`[${role}] ${body}`)
  }
  return lines.join('\n')
}
