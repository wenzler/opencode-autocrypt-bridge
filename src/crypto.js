import { readFileSync } from 'node:fs'
import * as openpgp from 'openpgp'
import { armorToBase64, normalizeBase64 } from './headers.js'

// armorToBase64 is exported from headers.js so config loading can stay pure.

export async function loadIdentity(ctx, cfg) {
  let armored = cfg.key.privateKeyArmored
  if (!armored && cfg.key.privateKeyFile) armored = readFileSync(cfg.key.privateKeyFile, 'utf8')
  if (!armored) armored = await ctx.storage.get('autocrypt.privateKey')

  if (!armored && cfg.key.generate) {
    const generated = await openpgp.generateKey({
      type: 'ecc',
      curve: 'curve25519', // Ed25519 signing primary + Curve25519 encryption subkey
      userIDs: [{ name: cfg.displayName, email: cfg.address }],
      passphrase: cfg.key.passphrase || undefined,
      format: 'armored',
    })
    armored = generated.privateKey
    await ctx.storage.set('autocrypt.privateKey', armored)
  }
  if (!armored) {
    throw new Error('No OpenPGP key: set AC_PRIVATE_KEY, AC_PRIVATE_KEY_FILE, or leave AC_GENERATE_KEY enabled')
  }

  const stored = await openpgp.readPrivateKey({ armoredKey: armored })
  let privateKey = stored
  if (stored.isEncrypted) {
    if (!cfg.key.passphrase) throw new Error('OpenPGP private key is encrypted; set AC_KEY_PASSPHRASE')
    privateKey = await openpgp.decryptKey({ privateKey: stored, passphrase: cfg.key.passphrase })
  }
  const publicArmored = privateKey.toPublic().armor()
  return {
    privateKey,
    publicB64: armorToBase64(publicArmored),
    publicArmored,
  }
}

export async function readPeerKey(keydata) {
  return openpgp.readKey({
    binaryKey: Uint8Array.from(Buffer.from(normalizeBase64(keydata), 'base64')),
  })
}

/** Return the uppercase OpenPGP fingerprint of Autocrypt keydata. */
export async function keyFingerprint(keydata) {
  const key = await readPeerKey(keydata)
  return key.getFingerprint().toUpperCase()
}

/**
 * Fail early if the configured pinned key is not a usable public OpenPGP key.
 * When expectedFingerprint is given, the key must match that identity.
 * Returns the normalized fingerprint.
 */
export async function validatePublicKey(keyB64, expectedFingerprint) {
  const key = await readPeerKey(keyB64)
  if (key.isPrivate()) throw new Error('Pinned contact key must be a public key, not a private key')
  const fingerprint = key.getFingerprint().toUpperCase()
  const expected = expectedFingerprint ? String(expectedFingerprint).toUpperCase() : ''
  if (expected && fingerprint !== expected) {
    throw new Error(`Pinned contact key fingerprint ${fingerprint} does not match ${expected}`)
  }
  return fingerprint
}

export async function encryptMime(bytes, identity, peerKeys) {
  const keys = [await readPeerKey(identity.publicB64)]
  for (const keydata of peerKeys) {
    if (keydata && keydata !== identity.publicB64) keys.push(await readPeerKey(keydata))
  }
  const message = await openpgp.createMessage({ binary: Uint8Array.from(bytes) })
  return openpgp.encrypt({
    message,
    encryptionKeys: keys,
    signingKeys: identity.privateKey,
    format: 'armored',
  })
}

/** Encrypt an inner MIME entity with a shared secret, as SecureJoin v3 uses. */
export async function encryptMimeWithPassword(bytes, sharedSecret, identity) {
  const message = await openpgp.createMessage({ binary: Uint8Array.from(bytes) })
  return openpgp.encrypt({
    message,
    passwords: [String(sharedSecret)],
    signingKeys: identity?.privateKey,
    format: 'armored',
  })
}

/**
 * Decrypt a SecureJoin v3 message that was encrypted with a shared secret.
 * Returns the signature state so callers can first learn a key, then require
 * that the same pinned key signed the message.
 */
export async function decryptMessageWithPasswordDetailed(armored, sharedSecret, verificationKeyB64) {
  const message = await openpgp.readMessage({ armoredMessage: armored })
  const verificationKeys = verificationKeyB64 ? [await readPeerKey(verificationKeyB64)] : undefined
  const result = await openpgp.decrypt({
    message,
    passwords: [String(sharedSecret)],
    ...(verificationKeys ? { verificationKeys } : {}),
    format: 'binary',
  })
  const signatureVerified = Boolean(result.signatures?.length)
  if (verificationKeyB64 && signatureVerified) {
    await Promise.all(result.signatures.map((signature) => signature.verified))
  }
  return { data: Buffer.from(result.data), signatureVerified }
}

/** Backwards-compatible password decrypt that returns only the plaintext. */
export async function decryptMessageWithPassword(armored, sharedSecret, verificationKeyB64) {
  const { data } = await decryptMessageWithPasswordDetailed(armored, sharedSecret, verificationKeyB64)
  return data
}

/**
 * Decrypt PGP/MIME. When verificationKeyB64 is supplied, require a valid
 * signature from that exact key.
 */
export async function decryptMessage(armored, identity, verificationKeyB64) {
  const message = await openpgp.readMessage({ armoredMessage: armored })
  const verificationKeys = verificationKeyB64 ? [await readPeerKey(verificationKeyB64)] : undefined
  const result = await openpgp.decrypt({
    message,
    decryptionKeys: [identity.privateKey],
    ...(verificationKeys ? { verificationKeys } : {}),
    format: 'binary',
  })
  if (verificationKeyB64) {
    if (!result.signatures?.length) throw new Error('Encrypted message has no OpenPGP signature')
    await Promise.all(result.signatures.map((signature) => signature.verified))
  }
  return {
    data: Buffer.from(result.data),
    signatureVerified: Boolean(verificationKeyB64 && result.signatures?.length),
  }
}
