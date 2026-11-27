/** Browser-safe value helpers shared by the GUI, settings and mail config. */

/** Keep IMAP/SMTP fields as hostnames even if a form adds a URL scheme. */
export function normalizeHost(value) {
  let host = String(value ?? '').trim()
  host = host.replace(/^[a-z][a-z\d+.-]*:\/\//i, '')
  host = host.replace(/^.*@/, '')
  host = host.split(/[/?#]/, 1)[0]
  return host.toLowerCase()
}

export function positiveInteger(value, fallback) {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback
}
