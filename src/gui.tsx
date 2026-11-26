import { createSignal, onCleanup, onMount } from "solid-js"
import { Plugin, SettingsPage } from "@opencode/plugin/gui"
import { QuestionBridge } from "./question-ipc"
import { BridgeRpc } from "./rpc.js"

export default Plugin.define({
  setup(ctx) {
    const rpc = () => ctx.client.rpc(BridgeRpc)
    const ui = ctx.ui

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
      const [newTitle, setNewTitle] = createSignal("")
      const [newDirectory, setNewDirectory] = createSignal("")
      const [secureJoinUri, setSecureJoinUri] = createSignal("")

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
          if (!sessionID()) setSessionID(nextSessions.boundSessionID || "")
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
        const lines = [
          `Email-bound session: ${catalog.boundSessionID || "(none)"}`,
          `Projects: ${catalog.projects?.length || 0} · Sessions: ${catalog.sessions.length}`,
          "",
        ]
        for (const project of (catalog.projects || []).slice(0, 8)) {
          lines.push(`${project.directory || project.id || "(unknown directory)"} [${project.id || "unknown"}]`)
          const inProject = catalog.sessions
            .filter((entry) => entry.projectID === project.id && entry.directory === project.directory)
            .slice(0, 12)
          for (const entry of inProject) {
            lines.push(`  ${entry.id}  ${entry.title}${entry.id === catalog.boundSessionID ? "  [bound]" : ""}`)
          }
        }
        return lines.join("\n")
      }

      const bindSession = () => run("Session bound", () => rpc().bindSession({ sessionID: sessionID().trim() }))
      const createSession = () => run("Session created", () => rpc().createSession({
        title: newTitle().trim(),
        directory: newDirectory().trim(),
      }))

      const fillFromInvite = async () => {
        setBusy(true)
        setMessage("")
        try {
          const parsed = await rpc().parseInvite({ invite: value("inviteUrl") })
          if (!parsed.fingerprint) throw new Error("Invite contains no OpenPGP fingerprint")
          setField("pinnedFingerprint", parsed.fingerprint)
          if (parsed.address) setField("pinnedContact", parsed.address)
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

      const save = () => {
        const payload = {
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
          requireEncrypted: checked("requireEncrypted"),
          pollIntervalMs: number("pollIntervalMs", 30000),
          verifyCertificate: checked("verifyCertificate"),
          privateKeyArmored: value("privateKeyArmored"),
          keyPassphrase: value("keyPassphrase"),
          generateKey: checked("generateKey"),
          preferEncryptMutual: checked("preferEncryptMutual"),
          defaultSessionID: value("defaultSessionID"),
          defaultSessionDirectory: value("defaultSessionDirectory"),
          emailDecisions: checked("emailDecisions"),
          emailHighRiskDecisions: checked("emailHighRiskDecisions"),
          emailQuestions: checked("emailQuestions"),
          emailPeek: checked("emailPeek"),
          emailTail: checked("emailTail"),
          emailSendFiles: checked("emailSendFiles"),
          emailWatch: checked("emailWatch"),
          emailReadReceipts: checked("emailReadReceipts"),
        }
        return run("Settings saved", () => rpc().updateSettings(payload))
      }

      const statusText = () => {
        const current = status()
        if (!current) return "Loading…"
        const lines = [
          `Configured: ${current.configured ? "yes" : "no"}`,
          `Running: ${current.running ? "yes" : "no"}`,
          `Remote type: ${value("remoteMode") || "securejoin"}`,
          `Bridge fingerprint (QR): ${current.selfFingerprint || "(none)"}`,
          `Pinned contact: ${current.pinnedContact || "(none)"}`,
          `Pinned contact fingerprint: ${current.pinnedFingerprint || "(none)"}`,
          `Learned contact fingerprint: ${current.learnedFingerprint || "(none)"}`,
          `Established: ${current.established ? "yes" : "no"}`,
          `Fingerprint verified: ${current.verified ? "yes" : "no"}`,
          `Session: ${current.sessionID || "(none)"}${current.sessionTitle ? ` — ${current.sessionTitle}` : ""}`,
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
          </ui.SettingsSection>

          <ui.SettingsSection title="Contact gate">
            <ui.SettingsRow id="remoteMode" title="Remote type" description="SecureJoin is for Delta Chat and performs a QR handshake. Autocrypt is the legacy mode for generic OpenPGP mail clients.">
              <ui.Select
                label="Remote type"
                value={mode()}
                onChange={(v) => setField("remoteMode", v)}
                options={[
                  { value: "securejoin", label: "SecureJoin (Delta Chat)" },
                  { value: "autocrypt", label: "Autocrypt" },
                ]}
              />
            </ui.SettingsRow>
            <ui.SettingsRow id="inviteUrl" title="Contact invite URL (optional)" description="Local prefill only. The fingerprint, address and name are read from it; i=/s= are ignored and never stored. Nothing is fetched.">
              <ui.TextInput label="Contact invite URL" value={value("inviteUrl")} onInput={(v) => setField("inviteUrl", v)} placeholder="https://i.delta.chat/#FPR&v=3&a=you%40example.org" />
            </ui.SettingsRow>
            <ui.SettingsRow title="Fill gate from invite">
              <ui.Button size="small" disabled={busy()} onClick={() => void fillFromInvite()}>Fill fingerprint and contact</ui.Button>
            </ui.SettingsRow>
            <ui.SettingsRow id="pinnedContact" title="Pinned contact" description="Required. Only this address may drive OpenCode.">
              <ui.TextInput label="Pinned contact" value={value("pinnedContact")} onInput={(v) => setField("pinnedContact", v)} placeholder="you@example.org" />
            </ui.SettingsRow>
            <ui.SettingsRow id="pinnedFingerprint" title="Pinned fingerprint" description="Required for both modes. The contact's OpenPGP fingerprint. An invite-style link fills this and the pinned address locally.">
              <ui.TextInput label="Pinned fingerprint" value={value("pinnedFingerprint")} onInput={(v) => setField("pinnedFingerprint", v)} placeholder="669AE77C…" />
            </ui.SettingsRow>
            <ui.SettingsRow id="pinnedContactKey" title="Pinned public key (optional)" description={settings().hasPinnedContactKey ? "A key is saved; leave blank to keep it. It must match the fingerprint." : "Bootstrap key; otherwise learned during setup."}>
              <ui.TextInput label="Pinned public key" type="password" value="" onInput={(v) => setField("pinnedContactKey", v)} placeholder={settings().hasPinnedContactKey ? "Saved" : "Armored key or base64 keydata"} />
            </ui.SettingsRow>
          </ui.SettingsSection>

          {mode() === "securejoin" ? (
            <ui.SettingsSection title="SecureJoin setup (Delta Chat)">
              <ui.SettingsRow title="SecureJoin QR" description="Creates a one-time QR invite carrying this bridge’s fingerprint and address (shown in status above), not the pinned contact details. Scan it in Delta Chat; the contact key is accepted only if it matches the pinned fingerprint. After verification, plaintext mail is ignored.">
                <div>
                  <ui.Button size="small" disabled={busy()} onClick={() => void run("SecureJoin QR created", async () => {
                    const invite = await rpc().getSecureJoinQr({})
                    setSecureJoinUri(invite.uri)
                    return undefined
                  })}>Create SecureJoin QR</ui.Button>
                  {secureJoinUri() ? <ui.TextInput label="SecureJoin invite URI" value={secureJoinUri()} onInput={() => {}} /> : null}
                </div>
              </ui.SettingsRow>
            </ui.SettingsSection>
          ) : (
            <ui.SettingsSection title="Autocrypt setup">
              <ui.SettingsRow title="Autocrypt request" description="Sends a plaintext hello with this bridge’s Autocrypt header. When the pinned contact replies with a matching fingerprint, the key is learned and confirmed by an encrypted reply.">
                <ui.Button size="small" disabled={busy()} onClick={() => void run("Autocrypt request sent", () => rpc().startHandshake({}))}>Send Autocrypt request</ui.Button>
              </ui.SettingsRow>
              <ui.SettingsRow id="requireEncrypted" title="Reject plaintext inbound mail" description="When on, only encrypted prompts from the pinned contact are accepted. Replies stay OpenPGP-encrypted whenever the pinned key is known.">
                <ui.Switch label="Reject plaintext inbound mail" hideLabel checked={checked("requireEncrypted")} onChange={(v) => setField("requireEncrypted", v)} />
              </ui.SettingsRow>
            </ui.SettingsSection>
          )}

          <ui.SettingsSection title="Mailbox tools">
            <ui.SettingsRow title="Rescan existing mail" description="Reads mail already in the mailbox, including replies received before the bridge started. Duplicate prompts are ignored.">
              <ui.Button size="small" disabled={busy()} onClick={() => void run("Inbox rescanned", () => rpc().rescanInbox({}))}>Rescan inbox</ui.Button>
            </ui.SettingsRow>
            <ui.SettingsRow title="Reset learned key">
              <ui.Button size="small" variant="danger" disabled={busy()} onClick={() => void run("Contact reset", () => rpc().resetContact({}))}>Reset contact</ui.Button>
            </ui.SettingsRow>
          </ui.SettingsSection>

          <ui.SettingsSection title="Key and transport">
            <ui.SettingsRow title="Generate key" description="Generate an Ed25519/Cv25519 key on first run if none is imported.">
              <ui.Switch label="Generate key" hideLabel checked={checked("generateKey")} onChange={(v) => setField("generateKey", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="prefer-encrypt=mutual">
              <ui.Switch label="Prefer mutual encryption" hideLabel checked={checked("preferEncryptMutual")} onChange={(v) => setField("preferEncryptMutual", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Verify TLS certificates">
              <ui.Switch label="Verify TLS certificates" hideLabel checked={checked("verifyCertificate")} onChange={(v) => setField("verifyCertificate", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Poll interval (ms)">
              <ui.TextInput label="Poll interval" value={String(value("pollIntervalMs") || 30000)} onInput={(v) => setField("pollIntervalMs", Number(v))} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Imported private key" description={settings().hasPrivateKey ? "A private key is saved; leave blank to keep it." : undefined}>
              <ui.TextInput label="Imported private key" type="password" value="" onInput={(v) => setField("privateKeyArmored", v)} placeholder={settings().hasPrivateKey ? "Saved" : "Armored private key"} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Key passphrase" description={settings().hasKeyPassphrase ? "A passphrase is saved; leave blank to keep it." : undefined}>
              <ui.TextInput label="Key passphrase" type="password" value="" onInput={(v) => setField("keyPassphrase", v)} placeholder={settings().hasKeyPassphrase ? "Saved" : "Optional"} />
            </ui.SettingsRow>
          </ui.SettingsSection>

          <ui.SettingsSection title="Remote controls" description="All commands arrive as encrypted mail from the pinned contact. No shell or arbitrary remote command execution is added.">
            <ui.SettingsRow title="Permission decisions by email" description="Allow !approve and !deny for low- and medium-risk OpenCode permission requests.">
              <ui.Switch label="Permission decisions by email" hideLabel checked={checked("emailDecisions")} onChange={(v) => setField("emailDecisions", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="High-risk decisions by email" description="DANGER: also allow email approval of shell-like actions and file access outside the session project. Off by default.">
              <ui.Switch label="High-risk decisions by email" hideLabel checked={checked("emailHighRiskDecisions")} onChange={(v) => setField("emailHighRiskDecisions", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Multiple-choice answers by email" description="Allow !answer to complete OpenCode question forms from the phone. Requires OpenCode Desktop to be running.">
              <ui.Switch label="Multiple-choice answers by email" hideLabel checked={checked("emailQuestions")} onChange={(v) => setField("emailQuestions", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Session output by email" description="Allow !peek to read recent assistant output.">
              <ui.Switch label="Session output by email" hideLabel checked={checked("emailPeek")} onChange={(v) => setField("emailPeek", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Terminal tail by email" description="Allow !tail to read the session terminal tail.">
              <ui.Switch label="Terminal tail by email" hideLabel checked={checked("emailTail")} onChange={(v) => setField("emailTail", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Send project files by email" description="Allow !send to attach a file from the session project directory. Paths outside that project are refused.">
              <ui.Switch label="Send project files by email" hideLabel checked={checked("emailSendFiles")} onChange={(v) => setField("emailSendFiles", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Session watch subscriptions" description="Allow !watch and !unwatch to email completion, failure and idle notices for a session.">
              <ui.Switch label="Session watch subscriptions" hideLabel checked={checked("emailWatch")} onChange={(v) => setField("emailWatch", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Read receipts" description="Request encrypted read receipts for bridge mail and reply with an encrypted receipt when the pinned contact asks for one.">
              <ui.Switch label="Read receipts" hideLabel checked={checked("emailReadReceipts")} onChange={(v) => setField("emailReadReceipts", v)} />
            </ui.SettingsRow>
            <ui.SettingsRow title="Command reference" description="Reply !help in the encrypted email thread for the live command list and current gate state.">
              <ui.Code content={"!sessions · !use <id> · !new <title> in <project>\n!default · !status · !help\n!approve <code> once|always · !deny <code> [reason]\n!answer <code> <choice>[,choice][;choice…]\n!peek [session] [count] · !tail [lines]\n!send <project-file> · !watch [session] · !unwatch"} language="text" />
            </ui.SettingsRow>
          </ui.SettingsSection>

          <ui.SettingsSection title="Sessions">
            <ui.SettingsRow id="sessions" title="Open projects and sessions" description="Every outbound email carries [session:ses_…] in its subject, so Delta Chat replies stay in that OpenCode session. Email commands: !sessions, !use <id>, !new <title> in <project>, !default, !status.">
              <ui.Code content={sessionText()} language="text" />
            </ui.SettingsRow>
            <ui.SettingsRow title="Bind email default to session" description="Changes the session used by new, unthreaded email. Existing subjects keep their own session.">
              <div>
                <ui.TextInput label="Session ID" value={sessionID()} onInput={(v) => setSessionID(v)} placeholder="ses_..." />
                <ui.Button size="small" disabled={busy() || !sessionID().trim()} onClick={() => void bindSession()}>Bind session</ui.Button>
              </div>
            </ui.SettingsRow>
            <ui.SettingsRow title="Create and bind a session" description="Creates a session in a listed project directory and makes it the email default.">
              <div>
                <ui.TextInput label="Session title" value={newTitle()} onInput={(v) => setNewTitle(v)} />
                <ui.TextInput label="Project directory" value={newDirectory()} onInput={(v) => setNewDirectory(v)} placeholder="/path/to/project" />
                <ui.Button size="small" disabled={busy() || !newTitle().trim()} onClick={() => void createSession()}>Create & bind</ui.Button>
              </div>
            </ui.SettingsRow>
            <ui.SettingsRow title="Default session on startup" description="Optional. Overrides the auto-created email session; leave blank to keep the current behavior.">
              <div>
                <ui.TextInput label="Default session ID" value={value("defaultSessionID")} onInput={(v) => setField("defaultSessionID", v)} placeholder="ses_..." />
                <ui.TextInput label="Default project directory" value={value("defaultSessionDirectory")} onInput={(v) => setField("defaultSessionDirectory", v)} placeholder="/path/to/project" />
              </div>
            </ui.SettingsRow>
          </ui.SettingsSection>

          <ui.SettingsSection title="Status" footer={message() ? <ui.Markdown text={message()} /> : undefined}>
            <ui.SettingsRow title="Current state" description="Fill the fields above and click Save & restart. Until the required mail and pinned-contact fields are valid, the bridge stays unconfigured and sends nothing.">
              <ui.Code content={statusText()} language="text" />
            </ui.SettingsRow>
            <ui.SettingsRow title="Apply changes">
              <ui.Button variant="contrast" busy={busy()} onClick={() => void save()}>Save & restart</ui.Button>
            </ui.SettingsRow>
          </ui.SettingsSection>
        </ui.SettingsLayout>
      )
    }

    ctx.add(SettingsPage, {
      id: "autocrypt-bridge",
      title: "Autocrypt Bridge",
      entries: [
        { id: "address", title: "Bot address", keywords: "imap smtp email" },
        { id: "pinnedContact", title: "Pinned contact", keywords: "fingerprint gate openpgp" },
        { id: "remoteMode", title: "Remote type", keywords: "securejoin deltachat autocrypt" },
        { id: "inviteUrl", title: "Contact invite URL", keywords: "fingerprint prefill" },
        { id: "sessions", title: "Open sessions", keywords: "session project routing" },
        { id: "defaultSessionID", title: "Default session", keywords: "session project binding" },
        { id: "emailDecisions", title: "Remote controls", keywords: "permission decision question answer watch danger" },
        { id: "emailHighRiskDecisions", title: "High-risk email approval", keywords: "danger shell file access" },
        { id: "emailReadReceipts", title: "Read receipts", keywords: "mdn receipt confirmation" },
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
