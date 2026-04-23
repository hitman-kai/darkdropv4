/**
 * DarkDrop V4 — Claim Code Encoding/Decoding
 *
 * Format: darkdrop:v4:{cluster}:{asset}:{encryption}:{payload}
 *
 * Payload contents (JSON, then base64url):
 *   s: secret (base58)
 *   n: nullifier (base58)
 *   a: amount in lamports (string)
 *   b: blinding_factor (base58)
 *   i: leaf index in Merkle tree
 *   v: vault address (base58)
 *
 * Encryption modes:
 *   raw  — no encryption, anyone with code can claim
 *   aes  — AES-256-GCM, password required (hint prefix for quick check)
 *
 * Browser-compatible: uses Web Crypto API and base64url encoding.
 */

import bs58 from "bs58";

export type Cluster = "mainnet" | "devnet" | "localnet";
export type Asset = "sol" | "usdc";
export type Encryption = "raw" | "aes" | "pbkdf2";

export interface ClaimCodePayload {
  secret: bigint;
  nullifier: bigint;
  amount: bigint;
  blindingFactor: bigint;
  leafIndex: number;
  vaultAddress: string;
  // Base64url-encoded 672 bytes: root(32) || filled_subtrees[20 * 32].
  // Snapshotted immediately after create_drop so the claim works without
  // scanning event logs. Must be used within ROOT_HISTORY_SIZE=30 later
  // deposits — after that the snapshot root is rotated out of root_history.
  // Optional for backward compatibility with pre-snapshot claim codes.
  pathSnapshot?: string;
  // "standard" (absent or explicit) = base layer: claim_credit → withdraw_credit.
  // "pool" = note pool layer: claim_from_note_pool → withdraw_credit.
  // The claim page dispatches on this field.
  flavor?: "standard" | "pool";
}

export interface ClaimCode {
  version: "v4";
  cluster: Cluster;
  asset: Asset;
  encryption: Encryption;
  payload: ClaimCodePayload;
  passwordHint?: string;
}

/**
 * Encode a claim code to string format.
 */
export async function encodeClaimCode(
  payload: ClaimCodePayload,
  cluster: Cluster = "devnet",
  asset: Asset = "sol",
  password?: string
): Promise<string> {
  const jsonPayload = JSON.stringify({
    s: bigintToBase58(payload.secret),
    n: bigintToBase58(payload.nullifier),
    a: payload.amount.toString(),
    b: bigintToBase58(payload.blindingFactor),
    i: payload.leafIndex,
    v: payload.vaultAddress,
    ...(payload.pathSnapshot ? { p: payload.pathSnapshot } : {}),
    ...(payload.flavor && payload.flavor !== "standard" ? { f: payload.flavor } : {}),
  });

  if (password) {
    const { encrypted, hint } = await encryptPayloadPBKDF2(jsonPayload, password);
    return `darkdrop:v4:${cluster}:${asset}:pbkdf2:${hint}:${encrypted}`;
  }

  const encoded = uint8ToBase64url(new TextEncoder().encode(jsonPayload));
  return `darkdrop:v4:${cluster}:${asset}:raw:${encoded}`;
}

/**
 * Decode a claim code string back to payload.
 */
export async function decodeClaimCode(
  code: string,
  password?: string
): Promise<ClaimCode> {
  const parts = code.split(":");
  if (parts[0] !== "darkdrop" || parts[1] !== "v4") {
    throw new Error("Invalid claim code: not a DarkDrop V4 code");
  }

  const cluster = parts[2] as Cluster;
  const asset = parts[3] as Asset;
  const encryption = parts[4] as Encryption;

  let jsonStr: string;
  let passwordHint: string | undefined;

  if (encryption === "pbkdf2") {
    if (!password) {
      throw new Error("Password required for encrypted claim code");
    }
    passwordHint = parts[5];
    const encryptedPayload = parts[6];
    jsonStr = await decryptPayloadPBKDF2(encryptedPayload, password);
  } else if (encryption === "aes") {
    // Legacy: SHA-256 derived key (decode-only for old claim codes)
    if (!password) {
      throw new Error("Password required for encrypted claim code");
    }
    passwordHint = parts[5];
    const encryptedPayload = parts[6];
    jsonStr = await decryptPayload(encryptedPayload, password);
  } else {
    const encoded = parts[5];
    jsonStr = new TextDecoder().decode(base64urlToUint8(encoded));
  }

  const parsed = JSON.parse(jsonStr);

  return {
    version: "v4",
    cluster,
    asset,
    encryption,
    passwordHint,
    payload: {
      secret: base58ToBigint(parsed.s),
      nullifier: base58ToBigint(parsed.n),
      amount: BigInt(parsed.a),
      blindingFactor: base58ToBigint(parsed.b),
      leafIndex: parsed.i,
      vaultAddress: parsed.v,
      pathSnapshot: parsed.p,
      flavor: parsed.f === "pool" ? "pool" : "standard",
    },
  };
}

// --- AES-256-GCM encryption (Web Crypto API) ---

async function deriveKey(password: string): Promise<CryptoKey> {
  const encoded = new TextEncoder().encode(password);
  const raw = await globalThis.crypto.subtle.digest(
    "SHA-256",
    encoded.buffer as ArrayBuffer
  );
  return globalThis.crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptPayload(
  plaintext: string,
  password: string
): Promise<{ encrypted: string; hint: string }> {
  const key = await deriveKey(password);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
      key,
      encoded.buffer as ArrayBuffer
    )
  );

  // Pack: iv (12) + ciphertext+tag (AES-GCM appends 16-byte tag)
  const packed = new Uint8Array(12 + ciphertext.length);
  packed.set(iv, 0);
  packed.set(ciphertext, 12);

  // Hint: first 8 hex chars of SHA-256("darkdrop-hint:" + password)
  const hintHash = new Uint8Array(
    await globalThis.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("darkdrop-hint:" + password).buffer as ArrayBuffer
    )
  );
  const hint = Array.from(hintHash.slice(0, 4))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return { encrypted: uint8ToBase64url(packed), hint };
}

async function decryptPayload(
  encrypted: string,
  password: string
): Promise<string> {
  const packed = base64urlToUint8(encrypted);
  const iv = packed.slice(0, 12);
  const ciphertext = packed.slice(12);

  const key = await deriveKey(password);
  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    ciphertext.buffer as ArrayBuffer
  );

  return new TextDecoder().decode(decrypted);
}

// --- PBKDF2 + AES-256-GCM encryption (stronger KDF) ---

const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_SALT_LEN = 16;

async function deriveKeyPBKDF2(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password).buffer as ArrayBuffer,
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return globalThis.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt.buffer as ArrayBuffer,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptPayloadPBKDF2(
  plaintext: string,
  password: string
): Promise<{ encrypted: string; hint: string }> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_LEN));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyPBKDF2(password, salt);
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
      key,
      encoded.buffer as ArrayBuffer
    )
  );

  // Pack: salt (16) + iv (12) + ciphertext+tag
  const packed = new Uint8Array(PBKDF2_SALT_LEN + 12 + ciphertext.length);
  packed.set(salt, 0);
  packed.set(iv, PBKDF2_SALT_LEN);
  packed.set(ciphertext, PBKDF2_SALT_LEN + 12);

  // Hint: first 8 hex chars of SHA-256("darkdrop-hint:" + password)
  const hintHash = new Uint8Array(
    await globalThis.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("darkdrop-hint:" + password).buffer as ArrayBuffer
    )
  );
  const hint = Array.from(hintHash.slice(0, 4))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return { encrypted: uint8ToBase64url(packed), hint };
}

async function decryptPayloadPBKDF2(
  encrypted: string,
  password: string
): Promise<string> {
  const packed = base64urlToUint8(encrypted);
  const salt = packed.slice(0, PBKDF2_SALT_LEN);
  const iv = packed.slice(PBKDF2_SALT_LEN, PBKDF2_SALT_LEN + 12);
  const ciphertext = packed.slice(PBKDF2_SALT_LEN + 12);

  const key = await deriveKeyPBKDF2(password, salt);
  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    ciphertext.buffer as ArrayBuffer
  );

  return new TextDecoder().decode(decrypted);
}

// --- Base64url encoding (browser-compatible, no Buffer) ---

function uint8ToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToUint8(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "===".slice(0, (4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// --- Base58 <-> BigInt ---

function bigintToBase58(val: bigint): string {
  const hex = val.toString(16);
  const paddedHex = hex.length % 2 === 0 ? hex : "0" + hex;
  const bytes = new Uint8Array(paddedHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(paddedHex.substr(i * 2, 2), 16);
  }
  return bs58.encode(bytes);
}

function base58ToBigint(str: string): bigint {
  const bytes = bs58.decode(str);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return BigInt("0x" + hex);
}
