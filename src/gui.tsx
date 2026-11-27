import { createSignal, onCleanup, onMount } from "solid-js"
import { Command, Plugin, SettingsPage, Slot } from "@opencode/plugin/gui"
import { QuestionBridge } from "./question-ipc"
import { BridgeRpc } from "./rpc.js"
import { secureJoinProgress, setupMarkdown, setupReadiness } from "./setup.js"

export default Plugin.define({
  setup(ctx) {
    const rpc = () => ctx.client.rpc(BridgeRpc)
    const ui = ctx.ui

    const bindCurrentSession = async (sessionID: string) => {
      try {
        await rpc().bindSession({ sessionID })
        ctx.toast.show({
          title: "Email bridge session switched",
          description: `A new email thread announces session ${sessionID}.`,
          variant: "success",
        })
      } catch (error) {
        ctx.toast.show({
          title: "Email bridge binding failed",
          description: error?.message || String(error),
          variant: "error",
        })
      }
    }

    const disableEmailBridge = async () => {
      try {
        await rpc().bindSession({ sessionID: "none" })
        ctx.toast.show({
          title: "Email bridge disabled",
          description: "No session is bound. Bind one here or reply !use <session> by email.",
          variant: "success",
        })
      } catch (error) {
        ctx.toast.show({
          title: "Email bridge binding failed",
          description: error?.message || String(error),
          variant: "error",
        })
      }
    }

    // Switch email to the session the user is looking at, without Settings.
    ctx.add(Command, {
      id: "bind-session",
      title: "Switch email bridge to this session",
      description: "Send a new email thread that switches Delta Chat to this OpenCode session.",
      keywords: "autocrypt email bridge bind session mail",
      section: "session",
      get enabled() {
        return Boolean(ctx.sessions.current())
      },
      run: () => {
        const current = ctx.sessions.current()
        if (current) void bindCurrentSession(current.id)
      },
    })

    ctx.add(Slot, {
      at: "session.location.menu",
      order: 20,
      render: (input) => (
        <>
          <ui.MenuSeparator />
          <ui.MenuItem
            label="Switch email to this session"
            onSelect={() => void bindCurrentSession(input.session.id)}
          />
        </>
      ),
    })

    ctx.add(Command, {
      id: "disable-email-bridge",
      title: "Disable email bridge",
      description: "Unbind the email session so incoming prompts are ignored until !use or a new binding.",
      keywords: "autocrypt email bridge disable off none session",
      section: "session",
      run: () => void disableEmailBridge(),
    })

    // Email answers arrive as an RPC event. This window forwards them to the
    // main process, which is the only place with session.form.reply().
    // Duplicate event deliveries must not produce a second form.reply; the
    // main provider below is the authoritative guard across windows too.
    const questionRpc = rpc()
    const forwardedQuestions = new Set<string>()
    onCleanup(questionRpc.events.on("questionAnswer", (event) => {
      const answer = event.data
      if (!answer.formID || forwardedQuestions.has(answer.formID)) return
      forwardedQuestions.add(answer.formID)
      void ctx.main(QuestionBridge).reply({
        sessionID: answer.sessionID,
        formID: answer.formID,
        answer: answer.answer,
      }).catch((error) => {
        forwardedQuestions.delete(answer.formID)
        ctx.toast.show({
          title: "Autocrypt question answer failed",
          description: error?.message || String(error),
          variant: "error",
        })
      })
    }))

    const Settings = () => {
      const [settings, setSettings] = createSignal({})
      const [status, setStatus] = createSignal(null)
      const [busy, setBusy] = createSignal(false)
      const [message, setMessage] = createSignal("")
      const [sessions, setSessions] = createSignal(null)
      const [sessionID, setSessionID] = createSignal("")
      const [mailTest, setMailTest] = createSignal(null)

      const reload = async () => {
        try {
          const [nextSettings, nextStatus, nextSessions] = await Promise.all([
            rpc().getSettings({}),
            rpc().getStatus({}),
            rpc().listSessions({}),
          ])
          setSettings(nextSettings)
          setStatus(nextStatus)
          setSessions(nextSessions)
          if (!sessionID()) setSessionID(nextSessions.emailDisabled ? "none" : (nextSessions.boundSessionID || ""))
          setMessage("")
        } catch (error) {
          setMessage(`Could not load settings: ${error.message || error}`)
        }
      }

      onMount(() => {
        void reload()
        const stop = rpc().events.on("status", (event) => setStatus(event.data))
        onCleanup(stop)
      })

      const defaults = {
        remoteMode: "securejoin",
        generateKey: true,
        preferEncryptMutual: true,
        verifyCertificate: true,
        emailDecisions: true,
        emailHighRiskDecisions: false,
        emailQuestions: true,
        emailPeek: true,
        emailTail: true,
        emailSendFiles: true,
        emailWatch: true,
        emailReadReceipts: true,
        emailProgress: true,
        emailProgressIntervalMs: 20000,
      }
      const setField = (key, value) => setSettings((prev) => ({ ...prev, [key]: value }))
      const value = (key) => settings()[key] ?? ""
      const checked = (key) => {
        const current = settings()[key]
        return current === undefined ? Boolean(defaults[key]) : Boolean(current)
      }
      const mode = () => String(value("remoteMode") || "securejoin")
      const hostValue = (key) => {
        const text = String(value(key)).trim()
        return text.replace(/^[a-z][a-z\d+.-]*:\/\//i, "").replace(/^.*@/, "").split(/[/?#]/, 1)[0].toLowerCase()
      }
      const number = (key, fallback) => {
        const parsed = Number(value(key))
        return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
      }

      // A test only counts for the exact values shown in the form. Editing any
      // mail field invalidates it and re-locks the rest of setup.
      const mailTestKey = () => JSON.stringify([
        "address", "imapHost", "imapPort", "imapSecurity", "imapUser", "imapPassword", "imapMailbox",
        "smtpHost", "smtpPort", "smtpSecurity", "smtpUser", "smtpPassword",
        "verifyCertificate", "pollIntervalMs",
      ].map((key) => [key, value(key)]))
      const mailTestCurrent = () => Boolean(mailTest()?.ok && mailTest()?.key === mailTestKey())
      const readiness = () => setupReadiness(settings(), status(), {
        mailTestAvailable: true,
        mailTestOk: mailTestCurrent(),
      })
      const setupText = () => setupMarkdown(readiness())
      const setupBlocked = () => !readiness().steps.find((step) => step.id === "mail")?.done
      const join = () => secureJoinProgress(status() || {})
      const joinCancellable = () => join().pending || join().failed

      const testMail = async () => {
        const key = mailTestKey()
        setBusy(true)
        setMessage("")
        try {
          const result = await rpc().testMailAccount(settingsPayload())
          const ok = Boolean(result.imap && result.smtp)
          setMailTest({ ...result, ok, key })
          const detail = result.errors?.length ? ` — ${result.errors.join("; ")}` : ""
          setMessage(`${ok ? "IMAP and SMTP login succeeded" : "Mail account check failed"}${detail}`)
          ctx.toast.show({
            title: ok ? "Mail account OK" : "Mail account problem",
            description: detail ? result.errors.join("; ") : undefined,
            variant: ok ? "success" : "error",
          })
        } catch (error) {
          const text = error?.message || String(error)
          setMailTest({ ok: false, errors: [text], key })
          setMessage(text)
          ctx.toast.show({ title: "Mail account check failed", description: text, variant: "error" })
        } finally {
          setBusy(false)
        }
      }

      const run = async (label, action) => {
        setBusy(true)
        setMessage("")
        try {
          const next = await action()
          if (next) setStatus(next)
          await reload()
          ctx.toast.show({ title: label, variant: "success" })
        } catch (error) {
          const text = error?.message || String(error)
          setMessage(text)
          ctx.toast.show({ title: label, description: text, variant: "error" })
        } finally {
          setBusy(false)
        }
      }

      const sessionText = () => {
        const catalog = sessions()
        if (!catalog) return "Loading…"
        if (!catalog.sessions?.length) return "No open sessions found."
        const bound = catalog.sessions.find((entry) => entry.id === catalog.boundSessionID)
        const boundLabel = catalog.emailDisabled
          ? "DISABLED — no session bound"
          : bound
            ? `${bound.title} — ${bound.directory || bound.id}`
            : (catalog.boundSessionID || "(none)")
        const lines = [
          `Email session: ${boundLabel}`,
          `Projects: ${catalog.projects?.length || 0} · Sessions: ${catalog.sessions.length}`,
          "",
        ]
        for (const project of (catalog.projects || []).slice(0, 8)) {
          lines.push(`${project.directory || project.id || "(unknown directory)"} [${project.id || "unknown"}]`)
          const inProject = catalog.sessions
            .filter((entry) => entry.projectID === project.id && entry.directory === project.directory)
            .slice(0, 12)
          for (const entry of inProject) {
            const marker = entry.id === catalog.boundSessionID ? "  [bound]" : ""
            lines.push(`  ${entry.title} — ${entry.id}${marker}`)
          }
        }
        return lines.join("\n")
      }

      const sessionOptions = () => {
        const catalog = sessions()
        const options = [{
          value: "none",
          label: "None — disable email bridge",
        }]
        for (const entry of catalog?.sessions || []) {
          options.push({
            value: entry.id,
            label: `${entry.title}${entry.directory ? ` — ${entry.directory}` : ""}${entry.id === catalog?.boundSessionID ? "  (current)" : ""}`,
          })
        }
        if (catalog?.boundSessionID && !options.some((option) => option.value === catalog.boundSessionID)) {
          options.unshift({ value: catalog.boundSessionID, label: `${catalog.boundSessionID}  (current)` })
        }
        return options
      }

      const bindSession = () => run("Session switched", () => rpc().bindSession({ sessionID: sessionID().trim() }))
      const cancelJoin = () => run("SecureJoin cancelled", () => rpc().cancelSecureJoin({}))

      const fillFromInvite = async () => {
        setBusy(true)
        setMessage("")
        try {
          const parsed = await rpc().parseInvite({ invite: value("inviteUrl") })
          if (!parsed.fingerprint) throw new Error("Invite contains no OpenPGP fingerprint")
          setField("pinnedFingerprint", parsed.fingerprint)
          if (parsed.address) setField("pinnedContact", parsed.address)
          setField("secureJoinAuth", parsed.auth)
          setField("secureJoinName", parsed.name)
          setField("secureJoinVersion", parsed.version || "3")
          setField("secureJoinRelays", parsed.relays)
          setField("secureJoinInviteNumber", parsed.inviteNumber)
          if (!parsed.auth) {
            setMessage("Invite has no s= auth code; enter it manually below before starting SecureJoin.")
          }
          const details = [parsed.fingerprint, parsed.address, parsed.name].filter(Boolean).join(" · ")
          ctx.toast.show({ title: "Invite fields filled", description: details, variant: "success" })
        } catch (error) {
          const text = error?.message || String(error)
          setMessage(text)
          ctx.toast.show({ title: "Invite fields filled", description: text, variant: "error" })
        } finally {
          setBusy(false)
        }
      }

      const settingsPayload = () => ({
          address: value("address"),
          displayName: value("displayName"),
          imapHost: hostValue("imapHost"),
          imapPort: number("imapPort", 993),
          imapSecurity: value("imapSecurity") || "tls",
          imapUser: value("imapUser"),
          imapPassword: value("imapPassword"),
          imapMailbox: value("imapMailbox") || "INBOX",
          smtpHost: hostValue("smtpHost"),
          smtpPort: number("smtpPort", 465),
          smtpSecurity: value("smtpSecurity") || "tls",
          smtpUser: value("smtpUser"),
          smtpPassword: value("smtpPassword"),
          pinnedContact: value("pinnedContact"),
          pinnedFingerprint: value("pinnedFingerprint"),
          pinnedContactKey: value("pinnedContactKey"),
          inviteUrl: value("inviteUrl"),
          remoteMode: mode(),
          secureJoinAuth: value("secureJoinAuth"),
          secureJoinName: value("secureJoinName"),
          secureJoinVersion: value("secureJoinVersion") || "3",
          secureJoinRelays: value("secureJoinRelays"),
          secureJoinInviteNumber: value("secureJoinInviteNumber"),
          requireEncrypted: checked("requireEncrypted"),
          pollIntervalMs: number("pollIntervalMs", 30000),
          verifyCertificate: checked("verifyCertificate"),
          deleteAfterRead: checked("deleteAfterRead"),
          privateKeyArmored: value("privateKeyArmored"),
          keyPassphrase: value("keyPassphrase"),
          generateKey: checked("generateKey"),
          preferEncryptMutual: checked("preferEncryptMutual"),
          emailDecisions: checked("emailDecisions"),
          emailHighRiskDecisions: checked("emailHighRiskDecisions"),
          emailQuestions: checked("emailQuestions"),
          emailPeek: checked("emailPeek"),
          emailTail: checked("emailTail"),
          emailSendFiles: checked("emailSendFiles"),
          emailWatch: checked("emailWatch"),
          emailReadReceipts: checked("emailReadReceipts"),
          emailProgress: checked("emailProgress"),
          emailProgressIntervalMs: number("emailProgressIntervalMs", 20000),
      })

      const save = () => run("Settings saved", () => rpc().updateSettings(settingsPayload()))

      const statusText = () => {
        const current = status()
        if (!current) return "Loading…"
        const lines = [
          `Configured: ${current.configured ? "yes" : "no"}`,
          `Running: ${current.running ? "yes" : "no"}`,
          `Remote type: ${value("remoteMode") || "securejoin"}`,
          `Bridge fingerprint (sent in SecureJoin): ${current.selfFingerprint || "(none)"}`,
          `Pinned contact / invite issuer: ${current.pinnedContact || "(none)"}`,
          `Pinned contact fingerprint: ${current.pinnedFingerprint || "(none)"}`,
          `Learned contact fingerprint: ${current.learnedFingerprint || "(none)"}`,
          `SecureJoin auth present: ${current.secureJoin?.hasAuth ? "yes" : "no"}`,
          `SecureJoin version: ${current.secureJoin?.version || "3"}`,
          `Established: ${current.established ? "yes" : "no"}`,
          `Fingerprint verified: ${current.verified ? "yes" : "no"}`,
          `Session: ${current.emailDisabled ? "DISABLED (none bound)" : (current.sessionTitle || current.sessionID || "(none)")}${current.sessionDirectory ? ` — ${current.sessionDirectory}` : ""}`,
          `Session directory: ${current.sessionDirectory || "(unknown)"}`,
          `State: ${current.handshake}`,
          `SecureJoin: ${current.secureJoin?.status || "idle"}`,
          `Last read receipt: ${current.lastReceiptAt ? new Date(current.lastReceiptAt).toLocaleString() : "(none)"}`,
          ...(current.lastError ? [`Last error: ${current.lastError}`] : []),
        ]
        return lines.join("\n")
      }

      return (
        <ui.SettingsLayout
          title="Autocrypt Bridge"
          description="Drive OpenCode from an OpenPGP-capable email client over IMAP/SMTP, gated by one pinned contact and fingerprint."
          actions={<ui.Button onClick={() => void reload()} disabled={busy()}>Refresh</ui.Button>}
        >
          <ui.SettingsSection
            title="Setup guide"
            description="Start here. Fill the mail account fields, test them, then set up the pinned contact. Everything outside the mail account stays locked until the test passes with the current values."
          >
            <ui.SettingsRow
              title="Start here"
              description={
                <ui.Markdown
                  text={"1. Fill **Bot address**, IMAP and SMTP below.\n2. Click **Test IMAP + SMTP**.\n3. Only then paste the invite / fill the pinned contact and SecureJoin fields.\n4. Click **Save & restart**, then **Start SecureJoin**.\n\nChanging any mail field invalidates the test and locks setup again."}
                />
              }
            />
            {mode() === "securejoin" ? (
              <ui.SettingsRow
                title="SecureJoin connection"
                description={
                  <>
                    {join().pending ? <ui.Loader size="small" /> : null}
                    <ui.Markdown text={join().markdown} />
                  </>
                }
              >
                <ui.Button
                  size="small"
                  variant="danger"
                  disabled={busy() || !joinCancellable()}
                  onClick={() => void cancelJoin()}
                >
                  Cancel
                </ui.Button>
              </ui.SettingsRow>
            ) : null}
            <ui.SettingsRow title="Readiness" description={<ui.Markdown text={setupText()} />} />
          </ui.SettingsSection>

          <ui.SettingsSection title="Mail account">
            <ui.SettingsRow id="address" title="Bot address" description="The email address this bridge uses.">
              <ui.TextInput label="Bot address" value={value("address")} onInput={(v) => setField("address", v)} placeholder="bot@example.org" />
            </ui.SettingsRow>
            <ui.SettingsRow id="displayName" title="Display name" description="Shown as the sender name in replies.">
              <ui.TextInput label="Display name" value={value("displayName")} onInput={(v) => setField("displayName", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow id="imap" title="IMAP host" description="Hostname, port and security for incoming mail. Do not include https:// or a path.">
              <ui.TextInput label="IMAP server hostname" type="text" value={value("imapHost")} onInput={(v) => setField("imapHost", v)} placeholder="imap.example.org" />
            </ui.SettingsRow>
            <ui.SettingsRow title="IMAP port / security">
              <div>
                <ui.TextInput label="IMAP port" value={String(value("imapPort") || 993)} onInput={(v) => setField("imapPort", Number(v))} />
                <ui.Select
                  label="IMAP security"
                  value={value("imapSecurity") || "tls"}
                  onChange={(v) => setField("imapSecurity", v)}
                  options={[{ value: "tls", label: "TLS" }, { value: "starttls", label: "STARTTLS" }, { value: "plain", label: "Plain" }]}
                />
              </div>
            </ui.SettingsRow>
            <ui.SettingsRow title="IMAP login" description={settings().hasImapPassword ? "A password is saved; leave blank to keep it." : undefined}>
              <ui.TextInput label="IMAP user" value={value("imapUser")} onInput={(v) => setField("imapUser", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="IMAP password">
              <ui.TextInput label="IMAP password" type="password" value="" onInput={(v) => setField("imapPassword", v)} placeholder={settings().hasImapPassword ? "Saved" : "Required"} />
            </ui.SettingsRow>
            <ui.SettingsRow title="IMAP mailbox">
              <ui.TextInput label="IMAP mailbox" value={value("imapMailbox") || "INBOX"} onInput={(v) => setField("imapMailbox", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow id="smtp" title="SMTP host" description="Hostname, port and security for outgoing replies. Do not include https:// or a path.">
              <ui.TextInput label="SMTP server hostname" type="text" value={value("smtpHost")} onInput={(v) => setField("smtpHost", v)} placeholder="smtp.example.org" />
            </ui.SettingsRow>
            <ui.SettingsRow title="SMTP port / security">
              <div>
                <ui.TextInput label="SMTP port" value={String(value("smtpPort") || 465)} onInput={(v) => setField("smtpPort", Number(v))} />
                <ui.Select
                  label="SMTP security"
                  value={value("smtpSecurity") || "tls"}
                  onChange={(v) => setField("smtpSecurity", v)}
                  options={[{ value: "tls", label: "TLS" }, { value: "starttls", label: "STARTTLS" }, { value: "plain", label: "Plain" }]}
                />
              </div>
            </ui.SettingsRow>
            <ui.SettingsRow title="SMTP login" description={settings().hasSmtpPassword ? "A password is saved; leave blank to keep it." : undefined}>
              <ui.TextInput label="SMTP user" value={value("smtpUser")} onInput={(v) => setField("smtpUser", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="SMTP password">
              <ui.TextInput label="SMTP password" type="password" value="" onInput={(v) => setField("smtpPassword", v)} placeholder={settings().hasSmtpPassword ? "Saved" : "Required"} />
            </ui.SettingsRow>
            <ui.SettingsRow
              title="Test mail account"
              description={mailTest()
                ? `${mailTest().imap ? "IMAP login OK" : "IMAP failed"}; ${mailTest().smtp ? "SMTP auth OK" : "SMTP failed"}${mailTest().errors?.length ? ` — ${mailTest().errors.join("; ")}` : ""}`
                : "Checks IMAP login and SMTP authentication without sending a message. Run this before starting SecureJoin."}
            >
              <ui.Button size="small" disabled={busy() || !readiness().mailReady} onClick={() => void testMail()}>Test IMAP + SMTP</ui.Button>
            </ui.SettingsRow>
          </ui.SettingsSection>

          <ui.SettingsSection title="Contact gate">
            <ui.SettingsRow id="remoteMode" title="Remote type" description="SecureJoin joins a QR invite supplied by the pinned contact (Delta Chat or any compatible client). Autocrypt is the legacy key-discovery mode.">
              <ui.Select
                label="Remote type"
                disabled={setupBlocked()}
                value={mode()}
                onChange={(v) => setField("remoteMode", v)}
                options={[
                  { value: "securejoin", label: "SecureJoin (Delta Chat)" },
                  { value: "autocrypt", label: "Autocrypt" },
                ]}
              />
            </ui.SettingsRow>
            <ui.SettingsRow id="inviteUrl" title="Contact invite URL / invite fields" description="Paste the QR URL from the pinned contact. It fills the pin and SecureJoin fields locally; s= is kept locally as the handshake auth code. Display hides the secret and nothing is fetched.">
              <ui.TextInput label="Contact invite URL" disabled={setupBlocked()} value={value("inviteUrl")} onInput={(v) => setField("inviteUrl", v)} placeholder="OPENPGP4FPR:FPR#a=you%40example.org&n=Name&s=AUTH&v=3" />
            </ui.SettingsRow>
            <ui.SettingsRow title="Fill fields from invite">
              <ui.Button size="small" disabled={busy() || setupBlocked() || !value("inviteUrl").trim()} onClick={() => void fillFromInvite()}>Fill SecureJoin fields</ui.Button>
            </ui.SettingsRow>
            <ui.SettingsRow id="pinnedContact" title="Pinned contact" description="Required. Only this address may drive OpenCode.">
              <ui.TextInput label="Pinned contact" disabled={setupBlocked()} value={value("pinnedContact")} onInput={(v) => setField("pinnedContact", v)} placeholder="you@example.org" />
            </ui.SettingsRow>
            <ui.SettingsRow id="pinnedFingerprint" title="Pinned fingerprint" description="Required for both modes. The contact's OpenPGP fingerprint. An invite-style link fills this and the pinned address locally.">
              <ui.TextInput label="Pinned fingerprint" disabled={setupBlocked()} value={value("pinnedFingerprint")} onInput={(v) => setField("pinnedFingerprint", v)} placeholder="669AE77C…" />
            </ui.SettingsRow>
            <ui.SettingsRow id="pinnedContactKey" title="Pinned public key (optional)" description={settings().hasPinnedContactKey ? "A key is saved; leave blank to keep it. It must match the fingerprint." : "Bootstrap key; otherwise learned during setup."}>
              <ui.TextInput label="Pinned public key" type="password" disabled={setupBlocked()} value="" onInput={(v) => setField("pinnedContactKey", v)} placeholder={settings().hasPinnedContactKey ? "Saved" : "Armored key or base64 keydata"} />
            </ui.SettingsRow>
          </ui.SettingsSection>

          {mode() === "securejoin" ? (
            <ui.SettingsSection title="SecureJoin setup">
              <ui.SettingsRow title="Join the contact's invite" description={readiness().canStartSecureJoin
                ? "Ready. This bridge never creates a QR; it joins the invite supplied by the pinned contact."
                : `Not ready: ${readiness().next.hint || readiness().next.label}.`}>
                <ui.Button
                  size="small"
                  busy={busy() || join().pending}
                  disabled={setupBlocked() || !readiness().canStartSecureJoin}
                  onClick={() => void run("SecureJoin started", () => rpc().startSecureJoin({}))}
                >
                  Start SecureJoin
                </ui.Button>
              </ui.SettingsRow>
              <ui.SettingsRow id="secureJoinAuth" title="SecureJoin auth code (s=)" description={settings().hasSecureJoinAuth ? "An auth code is saved; leave blank to keep it. Paste a new s= value to replace it." : "Required. The s= auth code from the contact's invite URL."}>
                <ui.TextInput label="SecureJoin auth code" type="password" disabled={setupBlocked()} value="" onInput={(v) => setField("secureJoinAuth", v)} placeholder={settings().hasSecureJoinAuth ? "Saved" : "URL-safe auth code"} />
              </ui.SettingsRow>
              <ui.SettingsRow id="secureJoinName" title="Invite display name (n=)" description="Optional local copy of the name shown in the contact's invite.">
                <ui.TextInput label="Invite display name" disabled={setupBlocked()} value={value("secureJoinName")} onInput={(v) => setField("secureJoinName", v)} />
              </ui.SettingsRow>
              <ui.SettingsRow id="secureJoinVersion" title="SecureJoin version (v=)" description="Only contact SecureJoin v3 is supported.">
                <ui.TextInput label="SecureJoin version" disabled={setupBlocked()} value={value("secureJoinVersion") || "3"} onInput={(v) => setField("secureJoinVersion", v)} />
              </ui.SettingsRow>
              <ui.SettingsRow id="secureJoinRelays" title="Relay addresses (r=)" description="Optional local copy of invite relay addresses. The bridge still contacts only the pinned address.">
                <ui.TextInput label="Relay addresses" disabled={setupBlocked()} value={value("secureJoinRelays")} onInput={(v) => setField("secureJoinRelays", v)} />
              </ui.SettingsRow>
              <ui.SettingsRow id="secureJoinInviteNumber" title="Legacy invite number (i=/j=)" description="Optional local copy only. v3 uses the auth code above; legacy invite numbers are not used as v3 secrets.">
                <ui.TextInput label="Legacy invite number" disabled={setupBlocked()} value={value("secureJoinInviteNumber")} onInput={(v) => setField("secureJoinInviteNumber", v)} />
              </ui.SettingsRow>
            </ui.SettingsSection>
          ) : (
            <ui.SettingsSection title="Autocrypt setup">
              <ui.SettingsRow title="Autocrypt request" description={readiness().canStartHandshake
                ? "Ready. Sends a plaintext hello with this bridge’s Autocrypt header."
                : `Not ready: ${readiness().next.hint || readiness().next.label}.`}>
                <ui.Button
                  size="small"
                  busy={busy() || String(status()?.handshake || "") === "awaiting-reply"}
                  disabled={setupBlocked() || !readiness().canStartHandshake}
                  onClick={() => void run("Autocrypt request sent", () => rpc().startHandshake({}))}
                >
                  Send Autocrypt request
                </ui.Button>
              </ui.SettingsRow>
              <ui.SettingsRow id="requireEncrypted" title="Reject plaintext inbound mail" description="When on, only encrypted prompts from the pinned contact are accepted. Replies stay OpenPGP-encrypted whenever the pinned key is known.">
                <ui.Switch label="Reject plaintext inbound mail" hideLabel disabled={setupBlocked()} checked={checked("requireEncrypted")} onChange={(v) => setField("requireEncrypted", v)} />
              </ui.SettingsRow>
            </ui.SettingsSection>
          )}

          <ui.SettingsSection title="Mailbox tools">
            <ui.SettingsRow title="Rescan existing mail" description="Reads mail already in the mailbox, including replies received before the bridge started. Duplicate prompts are ignored.">
              <ui.Button size="small" disabled={busy() || setupBlocked()} onClick={() => void run("Inbox rescanned", () => rpc().rescanInbox({}))}>Rescan inbox</ui.Button>
            </ui.SettingsRow>
            <ui.SettingsRow id="deleteAfterRead" title="Delete mail after processing" description="When on, each message is expunged from the IMAP server after the bridge handles it successfully. Failed or oversized messages stay in the mailbox.">
              <ui.Switch label="Delete mail after processing" hideLabel disabled={setupBlocked()} checked={checked("deleteAfterRead")} onChange={(v) => setField("deleteAfterRead", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Reset learned key" description={readiness().canResetContact
              ? "Clears the learned key and handshake state. Required when changing the pinned contact."
              : "Nothing learned yet. Save & restart first, then reset when changing the pinned contact."}>
              <ui.Button size="small" variant="danger" disabled={busy() || setupBlocked() || !readiness().canResetContact} onClick={() => void run("Contact reset", () => rpc().resetContact({}))}>Reset contact</ui.Button>
            </ui.SettingsRow>
          </ui.SettingsSection>

          <ui.SettingsSection title="Key and transport">
            <ui.SettingsRow title="Generate key" description="Generate an Ed25519/Cv25519 key on first run if none is imported.">
              <ui.Switch label="Generate key" hideLabel disabled={setupBlocked()} checked={checked("generateKey")} onChange={(v) => setField("generateKey", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="prefer-encrypt=mutual">
              <ui.Switch label="Prefer mutual encryption" hideLabel disabled={setupBlocked()} checked={checked("preferEncryptMutual")} onChange={(v) => setField("preferEncryptMutual", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Verify TLS certificates">
              <ui.Switch label="Verify TLS certificates" hideLabel disabled={setupBlocked()} checked={checked("verifyCertificate")} onChange={(v) => setField("verifyCertificate", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Poll interval (ms)">
              <ui.TextInput label="Poll interval" disabled={setupBlocked()} value={String(value("pollIntervalMs") || 30000)} onInput={(v) => setField("pollIntervalMs", Number(v))} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Imported private key" description={settings().hasPrivateKey ? "A private key is saved; leave blank to keep it." : undefined}>
              <ui.TextInput label="Imported private key" type="password" disabled={setupBlocked()} value="" onInput={(v) => setField("privateKeyArmored", v)} placeholder={settings().hasPrivateKey ? "Saved" : "Armored private key"} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Key passphrase" description={settings().hasKeyPassphrase ? "A passphrase is saved; leave blank to keep it." : undefined}>
              <ui.TextInput label="Key passphrase" type="password" disabled={setupBlocked()} value="" onInput={(v) => setField("keyPassphrase", v)} placeholder={settings().hasKeyPassphrase ? "Saved" : "Optional"} />
            </ui.SettingsRow>
          </ui.SettingsSection>

          <ui.SettingsSection title="Remote controls" description="All commands arrive as encrypted mail from the pinned contact. No shell or arbitrary remote command execution is added.">
            <ui.SettingsRow title="Permission decisions by email" description="Allow !approve and !deny for low- and medium-risk OpenCode permission requests.">
              <ui.Switch label="Permission decisions by email" hideLabel disabled={setupBlocked()} checked={checked("emailDecisions")} onChange={(v) => setField("emailDecisions", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="High-risk decisions by email" description="DANGER: also allow email approval of shell-like actions and file access outside the session project. Off by default.">
              <ui.Switch label="High-risk decisions by email" hideLabel disabled={setupBlocked()} checked={checked("emailHighRiskDecisions")} onChange={(v) => setField("emailHighRiskDecisions", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Multiple-choice answers by email" description="Allow !answer to complete OpenCode question forms from the phone. Requires OpenCode Desktop to be running.">
              <ui.Switch label="Multiple-choice answers by email" hideLabel disabled={setupBlocked()} checked={checked("emailQuestions")} onChange={(v) => setField("emailQuestions", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Session output by email" description="Allow !peek to read recent assistant output.">
              <ui.Switch label="Session output by email" hideLabel disabled={setupBlocked()} checked={checked("emailPeek")} onChange={(v) => setField("emailPeek", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Terminal tail by email" description="Allow !tail to read the session terminal tail.">
              <ui.Switch label="Terminal tail by email" hideLabel disabled={setupBlocked()} checked={checked("emailTail")} onChange={(v) => setField("emailTail", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Send project files by email" description="Allow !send to attach a file from the session project directory. Paths outside that project are refused.">
              <ui.Switch label="Send project files by email" hideLabel disabled={setupBlocked()} checked={checked("emailSendFiles")} onChange={(v) => setField("emailSendFiles", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Session watch subscriptions" description="Allow !watch and !unwatch to email completion, failure and idle notices for a session.">
              <ui.Switch label="Session watch subscriptions" hideLabel disabled={setupBlocked()} checked={checked("emailWatch")} onChange={(v) => setField("emailWatch", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Read receipts" description="Request RFC 8098 read receipts for bridge mail and reply with an encrypted receipt when the pinned contact asks for one.">
              <ui.Switch label="Read receipts" hideLabel disabled={setupBlocked()} checked={checked("emailReadReceipts")} onChange={(v) => setField("emailReadReceipts", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Progressive replies" description="Send throttled working updates while OpenCode is still running. The final mail contains only the text not already mailed.">
              <ui.Switch label="Progressive replies" hideLabel disabled={setupBlocked()} checked={checked("emailProgress")} onChange={(v) => setField("emailProgress", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Progress interval (ms)" description="Minimum gap between progressive mails. Default 20000 (about 180 mails/hour).">
              <ui.TextInput label="Progress interval" disabled={setupBlocked()} value={String(value("emailProgressIntervalMs") || 20000)} onInput={(v) => setField("emailProgressIntervalMs", Number(v))} />
            </ui.SettingsRow>
            <ui.SettingsRow
              title="Command reference"
              description={
                <>
                  <ui.Markdown text="Reply !help in the encrypted email thread for the live command list and current gate state." />
                  <ui.Code content={"!sessions · !use <#n|id>|none · !new <title> in <project>\n!default · !status · !help\n!approve <code> once|always · !deny <code> [reason]\n!answer <code> <choice>[,choice][;choice…]\n!peek [session|#n] [count] · !tail [lines]\n!send <project-file> · !watch [session|#n] · !unwatch"} language="text" />
                </>
              }
            />
          </ui.SettingsSection>

          <ui.SettingsSection title="Sessions">
            <ui.SettingsRow
              id="sessions"
              title="Open projects and sessions"
              description={
                <>
                  <ui.Markdown text="Every outbound email carries the session marker in its subject, so Delta Chat replies stay in that OpenCode session. Email commands: !sessions, !session <#n>, !use <#n|id>, !new <title> in <project>, !default, !status." />
                  <ui.Code content={sessionText()} language="text" />
                </>
              }
            />
            <ui.SettingsRow
              id="emailSession"
              title="Email session"
              description="Pick any open session by title, or None to disable the bridge. Switching sends a new email thread whose subject selects that session; replies there continue it. While disabled, incoming prompts are ignored until !use or a new binding."
            >
              <div>
                <ui.Select
                  label="Session"
                  options={sessionOptions()}
                  value={sessionID() || (sessions()?.emailDisabled ? "none" : undefined)}
                  onChange={(value) => setSessionID(value)}
                  placeholder="Choose a session or None"
                  disabled={busy() || setupBlocked()}
                />
                <ui.Button size="small" disabled={busy() || setupBlocked() || !sessionID().trim()} onClick={() => void bindSession()}>Switch session</ui.Button>
              </div>
            </ui.SettingsRow>
          </ui.SettingsSection>

          <ui.SettingsSection title="Status" footer={message() ? <ui.Markdown text={message()} /> : undefined}>
            <ui.SettingsRow
              title="Current state"
              description={
                <>
                  <ui.Markdown text="Use the Setup guide above. Until mail, pin, auth and Apply are complete, the bridge stays unconfigured and sends nothing." />
                  <ui.Code content={statusText()} language="text" />
                </>
              }
            />
            <ui.SettingsRow title="Apply changes">
              <ui.Button variant="contrast" busy={busy()} disabled={setupBlocked()} onClick={() => void save()}>Save & restart</ui.Button>
            </ui.SettingsRow>
          </ui.SettingsSection>
        </ui.SettingsLayout>
      )
    }

    ctx.add(SettingsPage, {
      id: "autocrypt-bridge",
      title: "Autocrypt Bridge",
      entries: [
        { id: "setup", title: "Setup guide", keywords: "wizard checklist securejoin invite apply ready" },
        { id: "address", title: "Bot address", keywords: "imap smtp email" },
        { id: "pinnedContact", title: "Pinned contact", keywords: "fingerprint gate openpgp" },
        { id: "remoteMode", title: "Remote type", keywords: "securejoin deltachat autocrypt" },
        { id: "inviteUrl", title: "Contact invite URL", keywords: "fingerprint prefill" },
        { id: "sessions", title: "Open sessions", keywords: "session project routing" },
        { id: "emailSession", title: "Email session", keywords: "session project binding switch" },
        { id: "emailDecisions", title: "Remote controls", keywords: "permission decision question answer watch danger" },
        { id: "emailHighRiskDecisions", title: "High-risk email approval", keywords: "danger shell file access" },
        { id: "emailReadReceipts", title: "Read receipts", keywords: "mdn receipt confirmation" },
        { id: "emailProgress", title: "Progressive replies", keywords: "partial streaming updates working" },
        { id: "deleteAfterRead", title: "Delete after processing", keywords: "imap expunge mailbox cleanup" },
      ],
      render: () => <Settings />,
    })
  },
  main(ctx) {
    const answeredForms = new Set<string>()
    const provider = ctx.provide(QuestionBridge, {
      async reply(input) {
        if (!input.formID || answeredForms.has(input.formID)) return
        answeredForms.add(input.formID)
        const answer = Object.fromEntries(
          input.answer.map((entry) => [entry.key, entry.value]),
        )
        let ok = true
        let error = ""
        try {
          await ctx.client.session.form.reply({
            sessionID: input.sessionID,
            formID: input.formID,
            answer,
          })
        } catch (cause) {
          ok = false
          error = cause?.message || String(cause)
        }
        await ctx.client.rpc(BridgeRpc).reportQuestionReply({
          formID: input.formID,
          ok,
          error,
        }).catch(() => undefined)
        if (!ok) {
          answeredForms.delete(input.formID)
          throw new Error(error || "The desktop could not complete the form")
        }
      },
    })
    ctx.onCleanup(() => provider.dispose())
  },
})
