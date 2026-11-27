const ALIASES = {
  list: 'sessions',
  projects: 'sessions',
  commands: 'help',
  shortcuts: 'help',
  session: 'use',
  create: 'new',
  reset: 'default',
  reject: 'deny',
  decide: 'approve',
}

const SIMPLE_COMMANDS = new Set(['sessions', 'help', 'status', 'default', 'unwatch'])
const SUBJECT_MARKER = /\[session:([^\]]+)\]/i

/** Add or replace the routing marker in an outbound subject. */
export function withSessionSubject(subject, sessionID) {
  const base = String(subject || '')
    .replace(SUBJECT_MARKER, '')
    .replace(/\s+/g, ' ')
    .trim()
  if (!sessionID) return base
  const marker = `[session:${sessionID}]`
  return base ? `${base} ${marker}` : marker
}

/** Read the routing marker from an inbound subject. */
export function sessionFromSubject(subject) {
  const match = SUBJECT_MARKER.exec(String(subject || ''))
  return match ? match[1].trim() : ''
}

/** Parse a leading `!command` line. Returns null for ordinary prompts. */
export function parseSessionCommand(text) {
  const lines = String(text || '').replace(/\r\n/g, '\n').split('\n')
  const first = lines.findIndex((line) => line.trim())
  if (first < 0) return null
  const match = /^!([a-z]+)(?:\s+([\s\S]*))?$/i.exec(lines[first].trim())
  if (!match) return null
  const command = ALIASES[match[1].toLowerCase()] || match[1].toLowerCase()
  const argument = String(match[2] || '').trim()
  if (SIMPLE_COMMANDS.has(command)) return { command, argument: '', rest: '' }
  if (command === 'use') {
    const [id, ...rest] = argument.split(/\s+/)
    return { command, argument: id || '', rest: rest.join(' ').trim() }
  }
  if (command === 'new') return { command, argument, rest: '' }
  // Remote-control commands keep the first token as the selector/code and put
  // the remainder in `rest` (decision, answer choices, line counts, captions).
  const [selector, ...rest] = argument.split(/\s+/)
  return { command, argument: selector || '', rest: rest.join(' ').trim() }
}

export function normalizeMessageId(value) {
  return String(value || '')
    .replace(/[\r\n\x00-\x1f\x7f]/g, '')
    .trim()
    .replace(/[<>]/g, '')
    .slice(0, 512)
}

/** Project groups in the exact order shown by !sessions. */
function displayGroups(catalog) {
  const groups = new Map()
  for (const session of catalog?.sessions || []) {
    const key = `${session.projectID || ''}\u0000${session.directory || ''}`
    if (!groups.has(key)) {
      groups.set(key, {
        id: session.projectID || '',
        directory: session.directory || '(unknown directory)',
        updated: 0,
        sessions: [],
      })
    }
    const group = groups.get(key)
    group.updated = Math.max(group.updated, Number(session.updated) || 0)
    group.sessions.push(session)
  }
  return [...groups.values()]
    .sort((a, b) => b.updated - a.updated)
    .slice(0, 8)
}

/**
 * Sessions in the exact order shown by !sessions. Only numbered sessions can
 * be selected with `!use #n`, so formatting and resolution share this list.
 */
export function orderedSessions(catalog) {
  return displayGroups(catalog).flatMap((group) => group.sessions.slice(0, 12))
}

/** Resolve a session id, `#n` from !sessions, title fragment, project or directory. */
export function resolveSessionRef(sessions, ref, displayed = sessions) {
  const needle = String(ref || '').trim().toLowerCase()
  if (!needle) return undefined
  const numbered = /^#(\d+)$/.exec(needle)
  if (numbered) return (displayed || [])[Number(numbered[1]) - 1] || undefined
  const exact = sessions.find((session) => String(session.id).toLowerCase() === needle)
  if (exact) return exact
  const matches = sessions.filter((session) => (
    String(session.title || '').toLowerCase().includes(needle)
    || String(session.directory || '').toLowerCase() === needle
    || String(session.projectID || '').toLowerCase() === needle
  ))
  if (matches.length > 1) throw new Error(`Ambiguous session reference "${ref}"; use the full session id`)
  return matches[0]
}

/** Resolve a known project directory from a path or project id. */
export function resolveProjectDirectory(catalog, value) {
  const needle = String(value || '').trim().toLowerCase()
  if (!needle) return ''
  for (const session of catalog.sessions || []) {
    if (String(session.directory || '').toLowerCase() === needle) return session.directory
    if (String(session.projectID || '').toLowerCase() === needle) return session.directory
  }
  for (const project of catalog.projects || []) {
    if (String(project.directory || '').toLowerCase() === needle) return project.directory
    if (String(project.id || '').toLowerCase() === needle) return project.directory
  }
  return ''
}

/** Split `Title in <project>` into a create-session request. */
export function parseNewSessionArgs(catalog, argument, fallbackDirectory) {
  const raw = String(argument || '').trim()
  const match = /\s+in\s+(\S.*)$/i.exec(raw)
  const title = (match ? raw.slice(0, match.index) : raw).trim()
  const requestedDirectory = match ? match[1].trim() : ''
  const directory = requestedDirectory
    ? resolveProjectDirectory(catalog, requestedDirectory)
    : String(fallbackDirectory || '')
  if (requestedDirectory && !directory) {
    throw new Error(`Unknown project "${requestedDirectory}"; use !sessions to list projects`)
  }
  return { title: title || 'Autocrypt session', directory }
}

/** Compact, encrypted-readable inventory of open sessions grouped by project. */
export function formatSessionDirectory(catalog, boundSessionID = '', emailDisabled = false) {
  const groups = displayGroups(catalog)
  const total = (catalog?.sessions || []).length
  const lines = [`OpenCode sessions (${total}):`]
  if (emailDisabled) lines.push('Email bridge: DISABLED (no session bound; use !use <session-id|#n>)')
  let number = 0
  for (const group of groups) {
    lines.push(`Project ${group.directory}${group.id ? ` [${group.id}]` : ''}`)
    for (const session of group.sessions.slice(0, 12)) {
      number += 1
      const marker = session.id === boundSessionID ? '  [email-bound]' : ''
      lines.push(`  #${number}  ${session.id}  ${session.title || '(untitled)'}${marker}`)
    }
  }
  if (total > number) lines.push(`...and ${total - number} more sessions (not numbered)`)
  lines.push('')
  lines.push('Commands:')
  lines.push('  !sessions                 list projects and numbered sessions')
  lines.push('  !use <#n|session-id>      continue this email thread in that session')
  lines.push('  !session <#n|session-id>  alias for !use')
  lines.push('  !new <title> in <project> create a session in a listed project')
  lines.push('  !default                  return this thread to the email-bound session')
  lines.push('  !status                   show the current bridge binding')
  lines.push('  !watch [session-id|#n]    email result, failure and decision notices')
  lines.push('  !unwatch                  stop those notices')
  lines.push('  !help                     full remote-control command list')
  return lines.join('\n')
}
