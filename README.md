# opencode-autocrypt-bridge

An OpenCode **V2** plugin that drives OpenCode from a standard OpenPGP-capable email client over IMAP + SMTP. It ships a server plugin, an RPC contract, and an experimental OpenCode Desktop settings page.

Design rules:

- **Two remote modes:** SecureJoin joins the pinned contact's invite (Delta Chat or any compatible client) and verifies both keys; Autocrypt (legacy) discovers keys from `Autocrypt:` headers. Both use OpenPGP/MIME (RFC 3156). `Chat-Version: 1.0` is only a display-compatibility marker, not a handshake signal.
- **Hard gate:** `pinnedContact` plus the contact's OpenPGP `pinnedFingerprint` are mandatory in both modes. Messages from any other address are rejected before attachments are written.
- **Autocrypt headers stay on:** every outbound message keeps its own `Autocrypt:` header, including after the key has been learned. Autocrypt is stateful, so peers use these headers to track key state, rotations, and recovery. It does not re-run establishment or weaken the pin.
- **Invites come from the contact:** the bridge never generates a QR. A pasted invite URL (or manually entered fields) supplies the inviter's fingerprint/address/name and the `s=` auth code. The auth code is kept only in local settings and used solely for the IMAP/SMTP handshake; no URL is fetched.
- **No website calls:** the plugin never fetches the domain in an invite URL. All traffic is IMAP/SMTP to the configured mail host.
- **Session-aware email:** every outbound subject carries `[session:ses_…]`. Delta Chat keeps that subject on replies, so the bridge returns to the same OpenCode session even across projects. Threading headers and explicit email commands are also supported.
- **Guided setup:** the GUI starts with a numbered instruction, verifies IMAP/SMTP login separately, locks every other control until those exact mail values pass the test, and shows cancelable SecureJoin wire progress. Editing any mail field invalidates the test and re-locks setup.
- **Optional mailbox cleanup:** with **Delete mail after processing** enabled, the bridge expunges each message from IMAP only after handling it successfully. Failures and oversized messages stay in the mailbox.
- **No remote shell:** encrypted email can answer OpenCode permission requests, answer native multiple-choice question forms, read session output, send project files, and subscribe to session notices. It never exposes arbitrary shell execution.
- **Ported transport:** IMAP IDLE/checkpoint and SMTP sending patterns are adapted from the MIT-licensed [`opencode-email-sync`](https://github.com/Sponn/opencode-email-sync).

## Install

### 1. Install the plugin directory

```sh
mkdir -p ~/.config/opencode/plugins
cd ~/.config/opencode/plugins
git clone <this-repository> autocrypt-bridge
cd autocrypt-bridge
npm install
npm run build
```

`npm run build` compiles `src/gui.tsx` into `dist/gui-experimental.cjs` and bundles the server entry into `dist/index.cjs`. OpenCode Desktop's local-plugin loader cannot resolve bare npm imports, so both bundles are required.

### 2. Register it in global OpenCode config

OpenCode Desktop loads GUI plugins from the **global** `~/.config/opencode/opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "/home/YOU/.config/opencode/plugins/autocrypt-bridge"
    }
  ]
}
```

That is the whole one-time registration. Open **Settings → Autocrypt Bridge** and fill everything there; the plugin loads even before any settings exist and stays `unconfigured` until the required fields are valid. If you prefer, the same fields can be prefilled in the `options` object or with `AC_*` environment variables; GUI-saved values override both.

Use absolute paths. Ports **993 (IMAP)** and **465 (SMTP submission)** are implicit TLS, so set `imapSecurity`/`smtpSecurity` to `tls`. Use `starttls` only with servers that offer STARTTLS on ports such as 143/587.

### 3. Start OpenCode Desktop

OpenCode Desktop loads the plugin and **Settings → Autocrypt Bridge** appears. Config edits reload live; use `/reload` if you want to force a refresh. If the page is missing:

- confirm `dist/gui-experimental.cjs` and `dist/index.cjs` exist (`npm run build`);
- confirm the plugin is registered in the global config, not only a project config;
- check **Settings → Extensions → Plugins** to ensure the plugin GUI is enabled.

## Establish the pinned contact

Choose **Remote type** in the GUI first. Pinning is common to both modes. In SecureJoin the invite's leading fingerprint and `a=` address are the pinned contact (the invite issuer); the bridge offers its own fingerprint only inside the encrypted handshake as the joiner. The bridge never creates an invite, so it cannot make itself the pinned contact.

The **Setup guide** section is the intended path, especially when changing the pinned contact:

1. Fill the mail account fields and click **Test IMAP + SMTP**. This checks login only; it sends nothing. Until it succeeds with the current values, every other control in Settings is locked.
2. Paste the invite URL and click **Fill SecureJoin fields**, or enter the pinned address, fingerprint and auth code manually.
3. Click **Save & restart**. SecureJoin/handshake actions stay disabled until the live bridge uses these exact pinned values.
4. If a different contact was pinned before, click **Reset contact** to clear the old learned key and handshake state.
5. Click **Start SecureJoin** (or **Send Autocrypt request** in legacy mode). A spinner and checklist show `vc-request-pubkey` sent, `vc-pubkey` received, `vc-request-with-auth` sent, and `vc-contact-confirm` received. **Cancel** aborts a pending join and ignores late replies until you start again. **Rescan inbox** picks up replies delayed by greylisting.

### SecureJoin (contact invite, default)

1. In Delta Chat (or another SecureJoin client), show the invite QR for the contact that is allowed to drive OpenCode. Paste its URL into **Contact invite URL** and choose **Fill SecureJoin fields**, or enter every field manually: pinned fingerprint, pinned address, `s=` auth code, `n=` name, `v=` version and optional relay/legacy fields.
2. Choose **Start SecureJoin**. The bridge sends a symmetrically encrypted `vc-request-pubkey` to **only the pinned address**, using `securejoin/<pinned fingerprint>/<auth code>`.
3. The invite issuer replies with a signed, symmetrically encrypted `vc-pubkey`. The bridge accepts its key only when that signature and fingerprint match `pinnedFingerprint`.
4. The bridge sends a signed, encrypted `vc-request-with-auth` containing the invite auth code and the bridge's own fingerprint.
5. The issuer sends a signed, encrypted `vc-contact-confirm`. The bridge marks the contact verified and immediately sends one encrypted welcome mail with the live command list. While an auth code is configured and the handshake is pending, no normal mail drives OpenCode; after verification, plaintext is ignored.

The auth code is stored locally and hidden in the GUI. It is never sent outside the encrypted handshake. Group and broadcast invites are rejected; this bridge is a one-to-one remote control, not a group member.

### Autocrypt (legacy)

1. On startup, if no key is known for the pinned contact, the bridge sends one plaintext **Connect …** message carrying its own `Autocrypt:` header (at most once per day).
2. The pinned contact replies with an `Autocrypt:` header containing its public key.
3. The bridge computes the key's OpenPGP fingerprint and accepts it **only** if it matches `pinnedFingerprint`.
4. The bridge stores the key, marks the contact established, and immediately sends a signed + encrypted OpenPGP/MIME confirmation. That first message includes the live `!help` command list.
5. All subsequent replies from OpenCode are signed and encrypted to that key. The outbound `Autocrypt:` header remains present on every message.

Use **Send Autocrypt request** to trigger the hello again, and optionally enable **Reject plaintext inbound mail** after the key is known. **Reset contact** removes the learned key and returns the bridge to `idle`.

Every outbound message includes `Chat-Version: 1.0`. This is only a display-compatibility marker: chat clients that filter ordinary email would otherwise hide handshake mail and replies. It does not enable any invite or handshake protocol.

## Session routing

The bridge is aware of all OpenCode sessions visible to the server, grouped by project directory. Routing priority for an inbound email is:

1. an explicit command on the first line (`!use`, `!new`, `!default`);
2. the `[session:ses_…]` marker in the subject;
3. `In-Reply-To` / `References` matching a message the bridge previously sent;
4. the contact-specific `Autocrypt: <contact>` catch-all session, created on first use.

All outbound replies replace any stale marker with the session actually used, so a Delta Chat reply keeps pointing at the right session. Opening OpenCode never changes that binding; only an explicit switch does. The subject may look like:

```text
Re: Build the parser [session:ses_de802e102]
```

Send these commands from the pinned contact. They are IRC-style leading `!` lines, are encrypted like any other prompt, and `!help` returns the live list with the current gate state.

| Command | Meaning | Gate |
|---|---|---|
| `!sessions` | List open projects and sessions with their ids; aliases: `!list`, `!projects` | always |
| `!use <session-id> [question]` | Continue this email thread in another session; remaining text becomes the prompt. Alias: `!session` | always |
| `!use none [question]` | Disable email control: no session is bound and prompts are ignored until `!use <session>` or a GUI binding. Aliases: `off`, `disable` | always |
| `!new <title> in <project-directory>` | Create a session in a listed project and use it for this thread. Alias: `!create` | always |
| `!default` | Return this thread to the contact's catch-all session. Alias: `!reset` | always |
| `!status` | Show the bound session, encryption state, and remote-control gates | always |
| `!help` | Show the full command list and gate state; aliases: `!commands`, `!shortcuts` | always |
| `!approve <code> once\|always` | Answer a stalled OpenCode permission request. Alias: `!decide` | permission decisions |
| `!deny <code> [reason]` | Reject a permission request, with optional feedback. Alias: `!reject` | permission decisions |
| `!answer <code> <choice>[,choice][;choice…]` | Answer a native multiple-choice question form | questions |
| `!peek [session-id] [count]` | Read recent assistant output from a session | session output |
| `!tail [lines]` | Read the session terminal tail | terminal tail |
| `!send <project-file>` | Attach a file from the session project directory | file sending |
| `!watch [session-id]` | Email completion, failure, idle and decision notices for a session | watch |
| `!unwatch` | Stop notices for this contact | watch |

A bound `None` session disables the bridge: `!help`, `!sessions`, `!status`, `!unwatch`, `!use` and `!new` still work, but normal prompts are acknowledged and ignored. Watches are cleared when the bridge is disabled.

Session switches affect the email thread, not any global default. Use **Settings → Autocrypt Bridge → Email session** to pick an open session by title or **None** to disable; switching sends a new email thread with a fresh subject so Delta Chat continues in that session. While working in a session you can also run **Switch email bridge to this session** from the command palette, or use the project/location menu’s **Switch email to this session** item. A message with no session marker falls back to the contact's internal `Autocrypt: <contact>` catch-all. New sessions are created from the Desktop UI or with `!new <title> in <project>` from email. The agent also gets an `autocrypt_sessions` tool so it can answer questions about open projects live.

## Stalled decisions and multiple-choice questions

When OpenCode asks for a permission decision, the bridge emails the pinned contact a short `D-…` code, the action, the resources, and a risk label. Reply with `!approve` or `!deny`. The bridge calls `ctx.permission.reply`, so the desktop session continues instead of waiting forever.

Shell-like actions and access outside the session's project directory are **HIGH RISK**. They are shown in the email but refused from the phone unless **High-risk decisions by email** is explicitly enabled in the GUI. There is no `!exec`, `!sh`, or other arbitrary remote-command path.

OpenCode's native question tool appears as a `form.created` event with `metadata.kind === "question"`. The bridge converts its fields into a numbered menu and emails it with another short code. Reply `!answer CODE 1` (or `1;2,3` for several questions, commas for multi-select). The server plugin cannot complete a native form itself: it emits an encrypted `questionAnswer` RPC event, and the OpenCode Desktop GUI forwards the answer through its main-process IPC to `session.form.reply`. The desktop must be running for the form to be completed. A single terminal notice follows on the same email thread: completed, or failed with a retry hint. Duplicate `!answer` deliveries and duplicate `session.form.reply` calls are ignored, so one answer never produces both a completion and an error mail.

Read receipts follow **RFC 8098** (the current MDN standard, obsoleting RFC 3798) with Delta Chat's `Chat-Disposition-Notification-To` extension alongside the standard `Disposition-Notification-To` header. Every outbound mail asks the pinned contact for a receipt; every inbound request gets one encrypted `multipart/report` MDN with `Final-Recipient`, `Original-Message-ID`, `Disposition`, `Reporting-UA` and a null SMTP envelope sender. Incoming receipts are recorded in bridge state and shown as **Last read receipt** in GUI status; they never generate another chat message. Receipts can be turned off in **Remote controls**. Ordinary RFC 8098 mail clients are supported; plaintext receipts from non-pinned senders are still rejected by the hard gate.

If a session is busy, the next prompt is queued with OpenCode's `delivery: "queue"` and the phone gets a short acknowledgement. `!watch` subscribes the thread to completion, failure, idle and decision notices so queued work can be followed without polling.

While a session is working, `message.part.delta` text is sent as throttled "Working on …" emails on the same thread. The final mail contains only the text not already mailed, so one prompt never produces a duplicate terminal answer. The default interval is 20 seconds (about 180 mails/hour, below the practical 220/hour ceiling); it is configurable with `emailProgress` / `AC_EMAIL_PROGRESS` and `emailProgressIntervalMs` / `AC_EMAIL_PROGRESS_INTERVAL_MS`.

### Invite URL and manual parameters

A contact-invite URI such as this is accepted:

```text
https://i.delta.chat/#FPR&v=3&s=AUTHCODE&a=you%40example.org&n=Bot+contact
OPENPGP4FPR:FPR#v=3&s=AUTHCODE&a=you%40example.org&n=Bot+contact
```

**Fill SecureJoin fields** reads the leading fingerprint, `a=`, `n=`, `v=`, `s=`, `r=`, and `i=`/`j=` into the local form. `s=` is the auth code the bridge uses to join; the displayed URL hides it, but the saved settings keep it. Explicit pinned settings must agree with the invite. Every parameter can also be typed directly in **SecureJoin setup**, so a URL from any OpenPGP client is optional. An armored `pinnedContactKey` may be supplied as bootstrap verification material; it must match the pinned fingerprint.

## GUI settings

**Settings → Autocrypt Bridge** provides:

- **Setup guide**: a numbered **Start here** instruction, live checklist, mail-test-gated controls, cancelable SecureJoin wire progress, and the next missing step first;
- bot address, display name;
- IMAP/SMTP hostname (no `https://` or path), port, security, login, and passwords, plus **Test IMAP + SMTP**;
- **Remote type**: SecureJoin (Delta Chat) or Autocrypt; setup controls are grouped by mode;
- pinned contact, pinned fingerprint, optional pinned public key;
- optional invite URL and **Fill SecureJoin fields**;
- manual SecureJoin parameters: `s=` auth code, `n=` name, `v=` version, `r=` relays and legacy `i=`/`j=`, plus **Start SecureJoin**; **Send Autocrypt request** and reject plaintext inbound mail in Autocrypt mode (outbound replies stay encrypted when the pinned key is known);
- generated/imported OpenPGP identity and mutual-encryption preference;
- TLS verification and IMAP poll interval;
- live status via RPC events: configured/unconfigured state, remote mode, learned fingerprint, established state, fingerprint verification, SecureJoin status, bound session, last error;
- **Email session**: list open projects/sessions and switch the email thread to a session by title, or choose **None** to disable the bridge; the switch is announced as a new email thread. Session-screen command and location-menu item switch to the current session, and a command-palette action disables it;
- **Remote controls**: independent gates for permission decisions, high-risk email approval, questions, session output, terminal tail, project file sending, watch subscriptions, read receipts, and progressive replies with an adjustable interval;
- **Delete mail after processing** (off by default), **Rescan inbox**, **Reset contact**, and **Save & restart**.

Saved passwords and private keys are hidden; leaving a password field blank keeps the saved value.

## Settings reference

All fields can be set in the GUI, in the `options` object, or with environment variables. GUI-saved values win.

| GUI field / option | Environment variable | Meaning | Default |
|---|---|---|---|
| Bot address / `address` | `AC_ADDRESS` | Bot's full email address | required |
| Display name / `displayName` | `AC_DISPLAY_NAME` | Sender name in replies | local part of address |
| IMAP host / `imapHost` | `AC_IMAP_HOST` | IMAP hostname; any URL scheme/path is stripped | required |
| IMAP port / `imapPort` | `AC_IMAP_PORT` | IMAP port | `993` |
| IMAP security / `imapSecurity` | `AC_IMAP_SECURITY` | `tls`, `starttls`, `plain` | `tls` |
| IMAP user / `imapUser` | `AC_IMAP_USER` | IMAP login | address |
| IMAP password / `imapPassword` | `AC_IMAP_PASSWORD` | IMAP password | required |
| IMAP mailbox / `imapMailbox` | `AC_IMAP_MAILBOX` | Mailbox to watch | `INBOX` |
| SMTP host / `smtpHost` | `AC_SMTP_HOST` | SMTP hostname; any URL scheme/path is stripped | required |
| SMTP port / `smtpPort` | `AC_SMTP_PORT` | SMTP port | `465` |
| SMTP security / `smtpSecurity` | `AC_SMTP_SECURITY` | `tls`, `starttls`, `plain` | `tls` |
| SMTP user / `smtpUser` | `AC_SMTP_USER` | SMTP login | address |
| SMTP password / `smtpPassword` | `AC_SMTP_PASSWORD` | SMTP password | required |
| Remote type / `remoteMode` | `AC_REMOTE_MODE` | `securejoin` (contact invite) or `autocrypt` (legacy) | `securejoin` |
| Pinned contact / `pinnedContact` | `AC_PINNED_CONTACT` | Invite issuer and the only address allowed to drive OpenCode | required |
| Pinned fingerprint / `pinnedFingerprint` | `AC_PINNED_FINGERPRINT` | Invite issuer's OpenPGP fingerprint | required |
| Pinned public key / `pinnedContactKey` | `AC_PINNED_CONTACT_KEY` | Optional bootstrap key; must match the fingerprint | learned during setup |
| Invite URL / `inviteUrl` | `AC_INVITE_URL` | Contact's invite; `s=` auth code kept locally, hidden in GUI | empty |
| SecureJoin auth / `secureJoinAuth` | `AC_SECURE_JOIN_AUTH` | `s=` auth code; alternative to pasting a URL | from invite |
| SecureJoin name / `secureJoinName` | `AC_SECURE_JOIN_NAME` | `n=` invite display name | from invite |
| SecureJoin version / `secureJoinVersion` | `AC_SECURE_JOIN_VERSION` | `v=`; only `3` is supported | `3` |
| SecureJoin relays / `secureJoinRelays` | `AC_SECURE_JOIN_RELAYS` | Optional `r=` relay addresses copied locally | from invite |
| Legacy invite number / `secureJoinInviteNumber` | `AC_SECURE_JOIN_INVITE_NUMBER` | Optional `i=`/`j=` copy; not used as a v3 secret | from invite |
| Reject plaintext inbound / `requireEncrypted` | `AC_REQUIRE_ENCRYPTED` | Reject plaintext inbound prompts; does not turn off outbound encryption | `false` |
| Poll interval / `pollIntervalMs` | `AC_POLL_INTERVAL_MS` | IMAP reconciliation interval | `30000` |
| Verify TLS / `verifyCertificate` | `AC_VERIFY_CERTIFICATE` | Verify IMAP/SMTP certificates | `true` |
| Generate key / `generateKey` | `AC_GENERATE_KEY` | Generate a key on first run | `true` |
| `prefer-encrypt=mutual` / `preferEncryptMutual` | `AC_PREFER_ENCRYPT_MUTUAL` | Advertise mutual encryption | `true` |
| Imported private key / `privateKeyArmored` | `AC_PRIVATE_KEY` | Armored bot private key | generated on first run |
| Key passphrase / `keyPassphrase` | `AC_KEY_PASSPHRASE` | Passphrase for imported key | none |
| Permission decisions / `emailDecisions` | `AC_EMAIL_DECISIONS` | Allow `!approve` and `!deny` for low/medium-risk requests | `true` |
| High-risk email approval / `emailHighRiskDecisions` | `AC_EMAIL_HIGH_RISK_DECISIONS` | DANGER: allow email approval of shell-like actions and out-of-project file access | `false` |
| Multiple-choice answers / `emailQuestions` | `AC_EMAIL_QUESTIONS` | Allow `!answer` to complete native question forms via Desktop IPC | `true` |
| Session output / `emailPeek` | `AC_EMAIL_PEEK` | Allow `!peek` | `true` |
| Terminal tail / `emailTail` | `AC_EMAIL_TAIL` | Allow `!tail` | `true` |
| Send project files / `emailSendFiles` | `AC_EMAIL_SEND_FILES` | Allow `!send` for files inside the session project | `true` |
| Watch subscriptions / `emailWatch` | `AC_EMAIL_WATCH` | Allow `!watch` and `!unwatch` notices | `true` |
| Read receipts / `emailReadReceipts` | `AC_EMAIL_READ_RECEIPTS` | Request RFC 8098 encrypted receipts for outbound mail and answer receipt requests | `true` |
| Progressive replies / `emailProgress` | `AC_EMAIL_PROGRESS` | Mail throttled working updates while the agent runs | `true` |
| Progress interval / `emailProgressIntervalMs` | `AC_EMAIL_PROGRESS_INTERVAL_MS` | Minimum milliseconds between progressive mails | `20000` |
| Delete after processing / `deleteAfterRead` | `AC_DELETE_AFTER_READ` | Expunge each successfully handled message from the IMAP server | `false` |

## Messages and attachments

- **Inbound:** supported attachments (`jpg`, `png`, `gif`, `webp`, `html`, `txt`, `md`, `pdf`) are decoded from the possibly encrypted MIME part, written under `AC_ATTACHMENT_DIR` (default `.opencode/autocrypt-attachments`), and passed to `ctx.session.prompt` as file attachments. Oversized or unsupported files are skipped with a log line.
- **Outbound:** the agent can call `autocrypt_send_file({ path, text })` to attach a file from the current project to that session's reply. Paths outside the project are refused. The pinned contact can request the same with `!send <project-file>` when file sending is enabled.
- **Session artifacts:** files created inside the session project (mockup `html`, screenshots `png`/`jpg`, `pdf`, `txt`/`md`) appear as `file` parts in the session context and are attached to the final reply automatically when file sending is enabled. Images no longer carry an invalid `charset` parameter, so Delta Chat and ordinary mail clients render them. Files outside the project or over `AC_MAX_ATTACHMENT_BYTES` are skipped.
- Each pinned contact gets one default OpenCode session; subjects, threading headers and `!use`/`!new` can route any thread to any open session. Inbound Message-IDs dedupe prompts.

## Development

```sh
npm test          # helpers, config, crypto, Autocrypt and SecureJoin flows
npm run build     # rebuild dist/gui-experimental.cjs and dist/index.cjs
```

The IMAP/SMTP checkpoint logic is ported from `opencode-email-sync` (MIT); see [LICENSE](LICENSE).

## Limitations

- The GUI plugin API is experimental and tied to the pinned `@opencode/plugin` version.
- In Autocrypt mode this is Autocrypt Level 1: opportunistic encryption gated by a pinned fingerprint, not a verified-chat protocol. SecureJoin mode performs a verified handshake for the pinned contact.
- OpenPGP/MIME exposes `To`, `Subject`, and `Date` on the outside; there is no header protection.
- No group chats or reactions. Encrypted read receipts are supported.
- Native multiple-choice answers require OpenCode Desktop: the server plugin emits the answer event and the GUI performs `session.form.reply`.
- High-risk email approval is an explicit opt-in. It can approve shell-like permission prompts, so leave it off unless the phone is a trusted control surface.
- Do not run the bot account simultaneously in another mail client, otherwise IMAP checkpoints can race.
