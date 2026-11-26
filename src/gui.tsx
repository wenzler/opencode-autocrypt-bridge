import { createSignal, onCleanup, onMount } from "solid-js"
import { Plugin, SettingsPage } from "@opencode/plugin/gui"
import { BridgeRpc } from "./rpc.js"

export default Plugin.define({
  setup(ctx) {
    const rpc = () => ctx.client.rpc(BridgeRpc)
    const ui = ctx.ui

    const Settings = () => {
      const [settings, setSettings] = createSignal({})
      const [status, setStatus] = createSignal(null)
      const [busy, setBusy] = createSignal(false)
      const [message, setMessage] = createSignal("")

      const reload = async () => {
        try {
          const [nextSettings, nextStatus] = await Promise.all([rpc().getSettings({}), rpc().getStatus({})])
          setSettings(nextSettings)
          setStatus(nextStatus)
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

      const defaults = { generateKey: true, preferEncryptMutual: true, verifyCertificate: true }
      const setField = (key, value) => setSettings((prev) => ({ ...prev, [key]: value }))
      const value = (key) => settings()[key] ?? ""
      const checked = (key) => {
        const current = settings()[key]
        return current === undefined ? Boolean(defaults[key]) : Boolean(current)
      }
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
          requireEncrypted: checked("requireEncrypted"),
          pollIntervalMs: number("pollIntervalMs", 30000),
          verifyCertificate: checked("verifyCertificate"),
          privateKeyArmored: value("privateKeyArmored"),
          keyPassphrase: value("keyPassphrase"),
          generateKey: checked("generateKey"),
          preferEncryptMutual: checked("preferEncryptMutual"),
        }
        return run("Settings saved", () => rpc().updateSettings(payload))
      }

      const statusText = () => {
        const current = status()
        if (!current) return "Loading…"
        const lines = [
          `Configured: ${current.configured ? "yes" : "no"}`,
          `Running: ${current.running ? "yes" : "no"}`,
          `Pinned contact: ${current.pinnedContact || "(none)"}`,
          `Pinned fingerprint: ${current.pinnedFingerprint || "(none)"}`,
          `Learned fingerprint: ${current.learnedFingerprint || "(none)"}`,
          `Established: ${current.established ? "yes" : "no"}`,
          `Fingerprint verified: ${current.verified ? "yes" : "no"}`,
          `State: ${current.handshake}`,
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
            <ui.SettingsRow id="inviteUrl" title="Contact invite URL (optional)" description="Local prefill only. The fingerprint, address and name are read from it; i=/s= are ignored and never stored. Nothing is fetched.">
              <ui.TextInput label="Contact invite URL" value={value("inviteUrl")} onInput={(v) => setField("inviteUrl", v)} placeholder="https://i.delta.chat/#FPR&v=3&a=you%40example.org" />
            </ui.SettingsRow>
            <ui.SettingsRow title="Fill gate from invite">
              <ui.Button size="small" disabled={busy()} onClick={() => void fillFromInvite()}>Fill fingerprint and contact</ui.Button>
            </ui.SettingsRow>
            <ui.SettingsRow id="pinnedContact" title="Pinned contact" description="Required. Only this address may drive OpenCode.">
              <ui.TextInput label="Pinned contact" value={value("pinnedContact")} onInput={(v) => setField("pinnedContact", v)} placeholder="you@example.org" />
            </ui.SettingsRow>
            <ui.SettingsRow id="pinnedFingerprint" title="Pinned fingerprint" description="Required. The contact's OpenPGP fingerprint. An invite-style link fills this and the pinned address locally.">
              <ui.TextInput label="Pinned fingerprint" value={value("pinnedFingerprint")} onInput={(v) => setField("pinnedFingerprint", v)} placeholder="669AE77C…" />
            </ui.SettingsRow>
            <ui.SettingsRow id="pinnedContactKey" title="Pinned public key (optional)" description={settings().hasPinnedContactKey ? "A key is saved; leave blank to keep it. It must match the fingerprint." : "Bootstrap key; otherwise learned from the Autocrypt header."}>
              <ui.TextInput label="Pinned public key" type="password" value="" onInput={(v) => setField("pinnedContactKey", v)} placeholder={settings().hasPinnedContactKey ? "Saved" : "Armored key or base64 keydata"} />
            </ui.SettingsRow>
            <ui.SettingsRow id="requireEncrypted" title="Reject plaintext inbound mail" description="When on, only encrypted prompts from the pinned contact are accepted. This does not disable encryption for replies: replies stay OpenPGP-encrypted whenever the pinned Autocrypt key is known.">
              <ui.Switch label="Reject plaintext inbound mail" hideLabel checked={checked("requireEncrypted")} onChange={(v) => setField("requireEncrypted", v)} />
            </ui.SettingsRow>
          </ui.SettingsSection>

          <ui.SettingsSection title="Key establishment">
            <ui.SettingsRow title="Autocrypt request" description="Sends a plaintext hello with this bridge’s Autocrypt header. When the pinned contact replies with a matching fingerprint, the key is learned and confirmed by an encrypted reply.">
              <ui.Button size="small" disabled={busy()} onClick={() => void run("Autocrypt request sent", () => rpc().startHandshake({}))}>Send Autocrypt request</ui.Button>
            </ui.SettingsRow>
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
        { id: "inviteUrl", title: "Contact invite URL", keywords: "fingerprint prefill" },
      ],
      render: () => <Settings />,
    })
  },
})
