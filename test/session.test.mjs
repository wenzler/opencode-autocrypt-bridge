import test from 'node:test'
import assert from 'node:assert/strict'
import {
  formatSessionDirectory,
  normalizeMessageId,
  orderedSessions,
  parseNewSessionArgs,
  parseSessionCommand,
  resolveSessionRef,
  sessionFromSubject,
  withSessionSubject,
} from '../src/session.js'

const catalog = {
  sessions: [
    { id: 'ses_bridge', title: 'Autocrypt: contact', projectID: 'p1', directory: '/work/alpha', updated: 20 },
    { id: 'ses_main', title: 'Main project', projectID: 'p1', directory: '/work/alpha', updated: 10 },
    { id: 'ses_other', title: 'Other project', projectID: 'p2', directory: '/work/beta', updated: 30 },
  ],
  projects: [
    { id: 'p1', directory: '/work/alpha', sessionCount: 2, updated: 20 },
    { id: 'p2', directory: '/work/beta', sessionCount: 1, updated: 30 },
  ],
}

test('subject marker is replaced rather than stacked', () => {
  assert.equal(withSessionSubject('Re: Hello [session:ses_old]', 'ses_new'), 'Re: Hello [session:ses_new]')
  assert.equal(sessionFromSubject('Re: Hello [session:ses_new]'), 'ses_new')
  assert.equal(withSessionSubject('Hello', ''), 'Hello')
  assert.equal(sessionFromSubject('Hello'), '')
})

test('normalizeMessageId strips angle brackets', () => {
  assert.equal(normalizeMessageId(' <abc@example.org> '), 'abc@example.org')
})

test('session commands are parsed without consuming ordinary prompts', () => {
  assert.deepEqual(parseSessionCommand('!sessions'), { command: 'sessions', argument: '', rest: '' })
  assert.deepEqual(parseSessionCommand('!list'), { command: 'sessions', argument: '', rest: '' })
  assert.deepEqual(parseSessionCommand('!commands'), { command: 'help', argument: '', rest: '' })
  assert.deepEqual(parseSessionCommand('!shortcuts'), { command: 'help', argument: '', rest: '' })
  assert.deepEqual(parseSessionCommand('!use ses_main check the build'), {
    command: 'use',
    argument: 'ses_main',
    rest: 'check the build',
  })
  assert.deepEqual(parseSessionCommand('!session #3'), {
    command: 'use',
    argument: '#3',
    rest: '',
  })
  assert.deepEqual(parseSessionCommand('!new Fix parser in /work/alpha'), {
    command: 'new',
    argument: 'Fix parser in /work/alpha',
    rest: '',
  })
  assert.equal(parseSessionCommand('please check the build'), null)
})

test('session refs resolve by id, title and project, and reject ambiguity', () => {
  assert.equal(resolveSessionRef(catalog.sessions, 'ses_main').id, 'ses_main')
  assert.equal(resolveSessionRef(catalog.sessions, 'Other').id, 'ses_other')
  assert.equal(resolveSessionRef(catalog.sessions, '/work/beta').id, 'ses_other')
  assert.equal(resolveSessionRef(catalog.sessions, 'missing'), undefined)
  assert.throws(
    () => resolveSessionRef(catalog.sessions, 'project'),
    /Ambiguous session reference/,
  )
})

test('displayed sessions are numbered and resolve through #n', () => {
  const displayed = orderedSessions(catalog)
  assert.deepEqual(displayed.map((session) => session.id), ['ses_other', 'ses_bridge', 'ses_main'])
  assert.equal(resolveSessionRef(catalog.sessions, '#1', displayed).id, 'ses_other')
  assert.equal(resolveSessionRef(catalog.sessions, '#3', displayed).id, 'ses_main')
  assert.equal(resolveSessionRef(catalog.sessions, '#99', displayed), undefined)
  const text = formatSessionDirectory(catalog, 'ses_main')
  assert.match(text, /#1\s+ses_other\s+Other project/)
  assert.match(text, /#2\s+ses_bridge/)
  assert.match(text, /#3\s+ses_main\s+Main project\s+\[email-bound\]/)
})

test('new session arguments split title from a known project', () => {
  assert.deepEqual(parseNewSessionArgs(catalog, 'Fix parser in /work/alpha', '/work/alpha'), {
    title: 'Fix parser',
    directory: '/work/alpha',
  })
  assert.deepEqual(parseNewSessionArgs(catalog, 'Fix parser in p2', ''), {
    title: 'Fix parser',
    directory: '/work/beta',
  })
  assert.throws(() => parseNewSessionArgs(catalog, 'Fix parser in /unknown', ''), /Unknown project/)
})

test('session directory is readable from an encrypted mail client', () => {
  const text = formatSessionDirectory(catalog, 'ses_main')
  assert.match(text, /OpenCode sessions \(3\)/)
  assert.match(text, /#3\s+ses_main\s+Main project\s+\[email-bound\]/)
  assert.match(text, /!use <#n\|session-id>/)
  assert.match(text, /!new <title> in <project>/)
  assert.match(text, /!watch \[session-id\|#n\]/)
  assert.match(text, /!unwatch/)
})
