# opencode-autocrypt-bridge

An OpenCode **V2** plugin that drives OpenCode from a standard OpenPGP-capable email client over IMAP + SMTP. It ships a server plugin, an RPC contract, and an experimental OpenCode Desktop settings page.

Design rules:

- **One standard flow:** Autocrypt Level 1 key discovery (`Autocrypt:` headers) plus OpenPGP/MIME (RFC 3156). `Chat-Version: 1.0` is only a display-compatibility marker, not a handshake signal.
- **Hard gate:** `pinnedContact` plus the contact's OpenPGP `pinnedFingerprint` are mandatory. Messages from any other address are rejected before attachments are written.
- **Autocrypt headers stay on:** every outbound message keeps its own `Autocrypt:` header, including after the key has been learned. Autocrypt is stateful, so peers use these headers to track key state, rotations, and recovery. It does not re-run establishment or weaken the pin.
- **Invite links are local prefill only:** a contact URI can fill the pinned fingerprint/address/name. `i=`/`s=` tokens are ignored, stripped before storage, and never sent on the wire.
- **No website calls:** the plugin never fetches the domain in an invite URL. All traffic is IMAP/SMTP to the configured mail host.
- **Session-aware email:** every outbound subject carries `[session:ses_…]`. Delta Chat keeps that subject on replies, so the bridge returns to the same OpenCode session even across projects. Threading headers and explicit email commands are also supported.
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

1. On startup, if no key is known for the pinned contact, the bridge sends one plaintext **Connect …** message carrying its own `Autocrypt:` header (at most once per day).
2. The pinned contact replies with an `Autocrypt:` header containing its public key.
3. The bridge computes the key's OpenPGP fingerprint and accepts it **only** if it matches `pinnedFingerprint`.
4. The bridge stores the key, marks the contact established, and immediately sends a signed + encrypted OpenPGP/MIME confirmation.
5. All subsequent replies from OpenCode are signed and encrypted to that key. The outbound `Autocrypt:` header remains present on every message.

Use **Send Autocrypt request** in the GUI to trigger the hello again. **Reset contact** removes the learned key and returns the bridge to `idle`.

Every outbound message includes `Chat-Version: 1.0`. This is only a display-compatibility marker: chat clients that filter ordinary email would otherwise hide the hello and its replies. It does not enable any invite or handshake protocol.

## Session routing

The bridge is aware of all OpenCode sessions visible to the server, grouped by project directory. Routing priority for an inbound email is:

1. an explicit command on the first line (`!use`, `!new`, `!default`);
2. the `[session:ses_…]` marker in the subject;
3. `In-Reply-To` / `References` matching a message the bridge previously sent;
4. the default session bound to the pinned contact.

All outbound replies replace any stale marker with the session actually used, so a Delta Chat reply keeps pointing at the right session. The subject may look like:

```text
Re: Build the parser [session:ses_de802e102]
```

Send these commands from the pinned contact (they are gated and encrypted like any other prompt):

| Command | Meaning |
|---|---|
| `!sessions` | List open projects and sessions with their ids; aliases: `!list`, `!projects` |
| `!use <session-id>` | Continue this email thread in another session; remaining text on the same line becomes the prompt. Alias: `!session` |
| `!new <title> in <project-directory>` | Create a session in a listed project and use it for this thread. Alias: `!create` |
| `!default` | Return this thread to the email-bound default session. Alias: `!reset` |
| `!status` | Show the bound session and current bridge state |
| `!help` | Show the command list |

Session switches affect the email thread, not the global default. Use **Settings → Autocrypt Bridge → Sessions** to bind the default session, create a session in a listed project, or set a startup default. The agent also gets an `autocrypt_sessions` tool so it can answer questions about open projects live.

### Invite URL prefill (optional)

A contact-invite URI such as this is accepted:

```text
https://i.delta.chat/#FPR&v=3&i=…&s=…&a=you%40example.org&n=Bot+contact
```

The GUI button **Fill fingerprint and contact** reads only the public fields (leading fingerprint, `a=`, `n=`, `v=`). `i=`, `j=`, and `s=` are discarded locally: they are neither stored nor used on the wire. Explicit pinned settings still win and must agree with the invite. An armored public key can also be supplied as `pinnedContactKey`; it must match the pinned fingerprint and is used only as bootstrap material.

## GUI settings

**Settings → Autocrypt Bridge** provides:

- bot address, display name;
- IMAP/SMTP hostname (no `https://` or path), port, security, login, and passwords;
- pinned contact, pinned fingerprint, optional pinned public key;
- optional invite URL and **Fill fingerprint and contact**;
- reject plaintext inbound mail (outbound replies stay encrypted when the pinned key is known);
- generated/imported OpenPGP identity and mutual-encryption preference;
- TLS verification and IMAP poll interval;
- live status via RPC events: configured/unconfigured state, learned fingerprint, established state, fingerprint verification, bound session, last error;
- **Sessions**: list open projects/sessions, bind the email default, create a session in a listed project, optional startup default;
- **Send Autocrypt request**, **Rescan inbox**, **Reset contact**, and **Save & restart**.

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
| Pinned contact / `pinnedContact` | `AC_PINNED_CONTACT` | The only address allowed to drive OpenCode | required |
| Pinned fingerprint / `pinnedFingerprint` | `AC_PINNED_FINGERPRINT` | Contact's OpenPGP fingerprint | required unless `pinnedContactKey` is set |
| Pinned public key / `pinnedContactKey` | `AC_PINNED_CONTACT_KEY` | Optional bootstrap key; must match the fingerprint | learned from Autocrypt |
| Invite URL / `inviteUrl` | `AC_INVITE_URL` | Local pin prefill only; `i=`/`s=` stripped | empty |
| Reject plaintext inbound / `requireEncrypted` | `AC_REQUIRE_ENCRYPTED` | Reject plaintext inbound prompts; does not turn off outbound encryption | `false` |
| Poll interval / `pollIntervalMs` | `AC_POLL_INTERVAL_MS` | IMAP reconciliation interval | `30000` |
| Verify TLS / `verifyCertificate` | `AC_VERIFY_CERTIFICATE` | Verify IMAP/SMTP certificates | `true` |
| Generate key / `generateKey` | `AC_GENERATE_KEY` | Generate a key on first run | `true` |
| `prefer-encrypt=mutual` / `preferEncryptMutual` | `AC_PREFER_ENCRYPT_MUTUAL` | Advertise mutual encryption | `true` |
| Imported private key / `privateKeyArmored` | `AC_PRIVATE_KEY` | Armored bot private key | generated on first run |
| Key passphrase / `keyPassphrase` | `AC_KEY_PASSPHRASE` | Passphrase for imported key | none |
| Default session / `defaultSessionID` | `AC_SESSION_ID` | Start with this existing OpenCode session instead of auto-creating one | empty |
| Default project / `defaultSessionDirectory` | `AC_SESSION_DIRECTORY` | Directory used when auto-creating the email session | plugin location |

## Messages and attachments

- **Inbound:** supported attachments (`jpg`, `png`, `gif`, `webp`, `html`, `txt`, `md`, `pdf`) are decoded from the possibly encrypted MIME part, written under `AC_ATTACHMENT_DIR` (default `.opencode/autocrypt-attachments`), and passed to `ctx.session.prompt` as file attachments. Oversized or unsupported files are skipped with a log line.
- **Outbound:** the agent can call `autocrypt_send_file({ path, text })` to attach a file from the current project to that session's reply. Paths outside the project are refused.
- Each pinned contact gets one default OpenCode session; subjects, threading headers and `!use`/`!new` can route any thread to any open session. Inbound Message-IDs dedupe prompts.

## Development

```sh
npm test          # helpers, config, crypto, Autocrypt flow
npm run build     # rebuild dist/gui-experimental.cjs and dist/index.cjs
```

The IMAP/SMTP checkpoint logic is ported from `opencode-email-sync` (MIT); see [LICENSE](LICENSE).

## Limitations

- The GUI plugin API is experimental and tied to the pinned `@opencode/plugin` version.
- This is Autocrypt Level 1: opportunistic encryption gated by a pinned fingerprint, not a verified-chat protocol.
- OpenPGP/MIME exposes `To`, `Subject`, and `Date` on the outside; there is no header protection.
- No invite handshake protocol, group chats, reactions, or read receipts.
- Do not run the bot account simultaneously in another mail client, otherwise IMAP checkpoints can race.
