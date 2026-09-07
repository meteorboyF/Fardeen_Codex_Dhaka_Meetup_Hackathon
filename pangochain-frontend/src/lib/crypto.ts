/**
 * PangoChain Client-Side Cryptography
 *
 * All document encryption occurs here — plaintext NEVER leaves the browser.
 * Implements:
 *   - ECIES P-256 keypair generation (registration)
 *   - PBKDF2-SHA256 600k iterations (password key derivation)
 *   - AES-256-GCM document encryption/decryption
 *   - ECIES key wrapping (ECDH + AES-GCM) for sharing document keys
 */

const subtle = window.crypto.subtle

// ─── PBKDF2 ───────────────────────────────────────────────────────────────────
// Parameters per NIST SP 800-132 (2023): SHA-256, 600,000 iterations, 256-bit random salt per user.
const PBKDF2_ITERATIONS = 600_000 as const

export async function derivePbkdf2Key(password: string, saltBase64: string): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const salt = base64ToBytes(saltBase64)

  const baseKey = await subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'],
  )

  return subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

// ─── ECIES P-256 Keypair ──────────────────────────────────────────────────────

export interface EciesKeyPair {
  publicKeyJwk: JsonWebKey
  privateKeyEncryptedB64: string  // skU wrapped under PBKDF2-derived key
  saltB64: string                 // salt for PBKDF2 re-derivation on login
  ivB64: string                   // IV for private key ciphertext
}

export async function generateEciesKeypair(password: string): Promise<EciesKeyPair> {
  // 1. Generate ECDH P-256 keypair
  const keyPair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,   // extractable — we export the private key to wrap it
    ['deriveKey', 'deriveBits'],
  )

  const publicKeyJwk = await subtle.exportKey('jwk', keyPair.publicKey)
  const privateKeyRaw = await subtle.exportKey('pkcs8', keyPair.privateKey)

  // 2. Derive wrapping key from password via PBKDF2
  const saltBytes = crypto.getRandomValues(new Uint8Array(32))
  const saltB64 = bytesToBase64(saltBytes)
  const wrappingKey = await derivePbkdf2Key(password, saltB64)

  // 3. Encrypt private key under wrapping key (AES-256-GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    privateKeyRaw,
  )

  return {
    publicKeyJwk,
    privateKeyEncryptedB64: bytesToBase64(new Uint8Array(ciphertext)),
    saltB64,
    ivB64: bytesToBase64(iv),
  }
}

export async function unwrapPrivateKey(
  password: string,
  saltB64: string,
  ivB64: string,
  encryptedB64: string,
): Promise<CryptoKey> {
  const wrappingKey = await derivePbkdf2Key(password, saltB64)
  const iv = base64ToBytes(ivB64)
  const ciphertext = base64ToBytes(encryptedB64)

  const rawPrivateKey = await subtle.decrypt({ name: 'AES-GCM', iv }, wrappingKey, ciphertext)

  return subtle.importKey('pkcs8', rawPrivateKey, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits'])
}

// ─── AES-256-GCM Document Encryption ─────────────────────────────────────────

export interface EncryptedDocument {
  ciphertextB64: string
  ivB64: string
  hashB64: string             // hD: SHA-256 of original plaintext for on-chain anchoring
  ciphertextHashB64: string   // hC: SHA-256 of (IV ∥ D_enc) — the exact bytes pinned to IPFS
  keyB64: string              // raw AES-256 key bytes (base64) — wrap before sending to server
}

export async function encryptDocument(file: ArrayBuffer): Promise<EncryptedDocument> {
  // Fresh key + IV per document
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const [ciphertext, hashBuffer, rawKey] = await Promise.all([
    subtle.encrypt({ name: 'AES-GCM', iv }, key, file),
    subtle.digest('SHA-256', file),
    subtle.exportKey('raw', key),
  ])

  // hC = SHA-256(IV ∥ D_enc): hash the exact IPFS payload, which the server assembles as
  // iv(12) ∥ ciphertext (see DocumentService.storeDocument and SignDocumentModal's iv = first 12 bytes).
  const ciphertextBytes = new Uint8Array(ciphertext)
  const ipfsPayload = new Uint8Array(iv.length + ciphertextBytes.length)
  ipfsPayload.set(iv, 0)
  ipfsPayload.set(ciphertextBytes, iv.length)
  const ciphertextHashBuffer = await subtle.digest('SHA-256', ipfsPayload)

  return {
    ciphertextB64: bytesToBase64(ciphertextBytes),
    ivB64: bytesToBase64(iv),
    hashB64: bytesToBase64(new Uint8Array(hashBuffer)),
    ciphertextHashB64: bytesToBase64(new Uint8Array(ciphertextHashBuffer)),
    keyB64: bytesToBase64(new Uint8Array(rawKey)),
  }
}

export async function decryptDocument(
  ciphertextB64: string,
  ivB64: string,
  keyB64: string,
): Promise<ArrayBuffer> {
  const rawKey = base64ToBytes(keyB64)
  const iv = base64ToBytes(ivB64)
  const ciphertext = base64ToBytes(ciphertextB64)

  const key = await subtle.importKey('raw', rawKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt'])
  return subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
}

// ─── ECIES Key Wrapping (ECDH + AES-GCM) ────────────────────────────────────

/**
 * AAD binding the wrapped key to its intended recipient.
 *
 * Without it the AES-GCM tag authenticates only the wrapped bytes, so a token
 * is self-contained and carries no statement about who it was produced for.
 * Binding the recipient's user id means a token minted for one principal fails
 * authentication if presented under another identity, rather than decrypting
 * silently.
 *
 * The document id is deliberately NOT bound. On the upload path the owner's key
 * is wrapped before `POST /documents/upload` returns, and the document id is
 * assigned by the backend, so it does not exist at wrap time. Binding it would
 * require client-generated document identifiers — a design change, not a local
 * one. See the manuscript's AAD footnote.
 */
function recipientAad(recipientUserId: string): Uint8Array<ArrayBuffer> {
  // Copied into an explicitly ArrayBuffer-backed view: TextEncoder returns
  // Uint8Array<ArrayBufferLike>, which does not satisfy WebCrypto's BufferSource.
  const bytes = new TextEncoder().encode(`pangochain:wrap:v1:recipient=${recipientUserId}`)
  const out = new Uint8Array(new ArrayBuffer(bytes.length))
  out.set(bytes)
  return out
}

/**
 * Domain-separation label for the HKDF step below. Bumping the version here
 * changes every derived wrapping key, so it doubles as the wrap-scheme version.
 */
const HKDF_INFO = new TextEncoder().encode('pangochain:wrap:hkdf:v2')

/**
 * Derive the AES-256-GCM wrapping key from an ECDH agreement, interposing
 * HKDF-SHA256 over the raw shared secret rather than using it directly.
 *
 * WebCrypto's `deriveKey(ECDH → AES-GCM)` takes the leftmost 256 bits of the
 * raw shared secret — effectively the x-coordinate of the shared point — as the
 * key. That coordinate is a structured field element, not a uniform bit string,
 * and the security arguments for hybrid schemes assume a KDF has produced a
 * uniform key (NIST SP 800-56C; RFC 9180). We therefore derive the raw secret
 * with `deriveBits` and run it through HKDF-Extract-then-Expand. The ephemeral
 * public key travels with the token and supplies per-wrap freshness, so an empty
 * salt with a fixed domain-separation `info` label is sufficient and keeps the
 * token format byte-identical.
 */
async function deriveWrappingKey(
  ecdhPublic: CryptoKey,
  ecdhPrivate: CryptoKey,
  usage: KeyUsage,
): Promise<CryptoKey> {
  const sharedSecret = await subtle.deriveBits(
    { name: 'ECDH', public: ecdhPublic }, ecdhPrivate, 256,
  )
  const hkdfKey = await subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey'])
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: HKDF_INFO },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  )
}

/**
 * SHA-256 hex over the exact public-key JWK string the client fetched and is about to
 * wrap under (audit finding S4). Sent alongside the grant as the recipient-key
 * attestation, so the chaincode compares the key the wrap was actually produced under
 * against the enrollment-time anchor; a key substituted after the fetch, or restored
 * in the database before submission, still fails verification.
 */
export async function attestKeyHash(publicKeyJwkString: string): Promise<string> {
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(publicKeyJwkString))
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Wrap a document key (keyB64) with recipient's P-256 public key.
 * Uses ECDH + HKDF-SHA256 to derive a wrapping key, then AES-GCM to encrypt.
 * Output is a single base64 blob: ephemeralPubKey(65) || iv(12) || wrapped(32+16)
 *
 * `recipientUserId` is bound as AAD. It is optional only so that callers that
 * genuinely have no recipient identity keep compiling; omitting it reproduces
 * the original unbound token.
 */
export async function eciesWrapKey(
  recipientPublicKeyJwk: JsonWebKey,
  keyB64: string,
  recipientUserId?: string,
): Promise<string> {
  const recipientPubKey = await subtle.importKey(
    'jwk', recipientPublicKeyJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  )

  // Generate ephemeral keypair for this wrapping operation
  const ephemeral = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits'],
  )

  // ECDH shared secret → HKDF-SHA256 → AES-256-GCM wrapping key
  const wrappingKey = await deriveWrappingKey(recipientPubKey, ephemeral.privateKey, 'encrypt')

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const docKeyBytes = base64ToBytes(keyB64)
  const wrapped = await subtle.encrypt(
    recipientUserId
      ? { name: 'AES-GCM', iv, additionalData: recipientAad(recipientUserId) }
      : { name: 'AES-GCM', iv },
    wrappingKey,
    docKeyBytes,
  )

  // Export ephemeral public key in raw (uncompressed) form — 65 bytes
  const ephPubRaw = new Uint8Array(await subtle.exportKey('raw', ephemeral.publicKey))

  // Pack: [ephPubRaw(65) || iv(12) || wrapped(48)]
  const total = new Uint8Array(ephPubRaw.length + iv.length + wrapped.byteLength)
  total.set(ephPubRaw, 0)
  total.set(iv, ephPubRaw.length)
  total.set(new Uint8Array(wrapped), ephPubRaw.length + iv.length)

  return bytesToBase64(total)
}

/**
 * Unwrap a document key using the recipient's private ECDH key.
 *
 * When `recipientUserId` is supplied the recipient-bound AAD is required first.
 * Tokens minted before AAD binding carry no AAD and cannot be distinguished by
 * inspection — the format is byte-identical — so unwrapping falls back to the
 * unbound form rather than breaking every existing grant. Client-side keys mean
 * legacy tokens cannot be re-wrapped server-side; they are only replaced when a
 * grant is reissued.
 *
 * The fallback is therefore transitional and weakens the guarantee while it
 * exists: an attacker who can present a legacy-format token still gets the old
 * behaviour. Removing it requires reissuing outstanding grants, after which
 * `allowUnboundLegacy` should be set false.
 */
export async function eciesUnwrapKey(
  recipientPrivateKey: CryptoKey,
  wrappedTokenB64: string,
  recipientUserId?: string,
  allowUnboundLegacy = true,
): Promise<string> {
  const blob = base64ToBytes(wrappedTokenB64)

  const ephPubRaw = blob.slice(0, 65)
  const iv = blob.slice(65, 77)
  const wrapped = blob.slice(77)

  const ephPubKey = await subtle.importKey(
    'raw', ephPubRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  )

  const wrappingKey = await deriveWrappingKey(ephPubKey, recipientPrivateKey, 'decrypt')

  if (recipientUserId) {
    try {
      const bound = await subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: recipientAad(recipientUserId) },
        wrappingKey,
        wrapped,
      )
      return bytesToBase64(new Uint8Array(bound))
    } catch {
      if (!allowUnboundLegacy) {
        throw new Error('Wrapped key is not bound to this recipient')
      }
      // Fall through to the unbound form for pre-AAD tokens.
      console.warn(
        '[crypto] wrapped key carries no recipient binding (pre-AAD token); ' +
        'reissue this grant to bind it',
      )
    }
  }

  const rawKey = await subtle.decrypt({ name: 'AES-GCM', iv }, wrappingKey, wrapped)
  return bytesToBase64(new Uint8Array(rawKey))
}

// ─── ECDSA P-256 Keypair (signing) ───────────────────────────────────────────

export interface EcdsaKeyPair {
  publicKeyJwk: JsonWebKey
  privateKeyEncryptedB64: string
  saltB64: string
  ivB64: string
}

export async function generateEcdsaKeypair(password: string): Promise<EcdsaKeyPair> {
  const keyPair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )

  const publicKeyJwk = await subtle.exportKey('jwk', keyPair.publicKey)
  const privateKeyRaw = await subtle.exportKey('pkcs8', keyPair.privateKey)

  const saltBytes = crypto.getRandomValues(new Uint8Array(32))
  const saltB64 = bytesToBase64(saltBytes)
  const wrappingKey = await derivePbkdf2Key(password, saltB64)

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, privateKeyRaw)

  return {
    publicKeyJwk,
    privateKeyEncryptedB64: bytesToBase64(new Uint8Array(ciphertext)),
    saltB64,
    ivB64: bytesToBase64(iv),
  }
}

export async function unwrapEcdsaPrivateKey(
  password: string,
  saltB64: string,
  ivB64: string,
  encryptedB64: string,
): Promise<CryptoKey> {
  const wrappingKey = await derivePbkdf2Key(password, saltB64)
  const iv = base64ToBytes(ivB64)
  const ciphertext = base64ToBytes(encryptedB64)
  const rawPrivateKey = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    ciphertext,
  )
  return subtle.importKey('pkcs8', rawPrivateKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
}

export async function signDocumentHash(hashB64: string, privateKey: CryptoKey): Promise<string> {
  const hashBytes = base64ToBytes(hashB64)
  const signature = await subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    privateKey,
    hashBytes,
  )
  return bytesToBase64(new Uint8Array(signature))
}

const ECDSA_KEY_PREFIX = 'pangochain_signing_key_'

export function storeWrappedEcdsaKey(userId: string, data: {
  encryptedB64: string
  saltB64: string
  ivB64: string
}) {
  localStorage.setItem(ECDSA_KEY_PREFIX + userId, JSON.stringify(data))
}

export function loadWrappedEcdsaKey(userId: string): {
  encryptedB64: string
  saltB64: string
  ivB64: string
} | null {
  const raw = localStorage.getItem(ECDSA_KEY_PREFIX + userId)
  return raw ? JSON.parse(raw) : null
}

// ─── Integrity Verification ──────────────────────────────────────────────────

export async function verifyIntegrity(plaintext: ArrayBuffer, expectedHashB64: string): Promise<boolean> {
  const hashBuffer = await subtle.digest('SHA-256', plaintext)
  const actualHashB64 = bytesToBase64(new Uint8Array(hashBuffer))
  return actualHashB64 === expectedHashB64
}

// ─── Local Key Storage (localStorage) ───────────────────────────────────────

const KEY_PREFIX = 'pangochain_key_'

export function storeWrappedPrivateKey(userId: string, data: {
  encryptedB64: string
  saltB64: string
  ivB64: string
}) {
  localStorage.setItem(KEY_PREFIX + userId, JSON.stringify(data))
}

export function loadWrappedPrivateKey(userId: string): {
  encryptedB64: string
  saltB64: string
  ivB64: string
} | null {
  const raw = localStorage.getItem(KEY_PREFIX + userId)
  return raw ? JSON.parse(raw) : null
}

export function clearStoredKey(userId: string) {
  localStorage.removeItem(KEY_PREFIX + userId)
}

// ─── Utility ─────────────────────────────────────────────────────────────────

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

export function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length) as Uint8Array<ArrayBuffer>
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
