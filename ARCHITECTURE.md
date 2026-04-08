# DARKDROP V4 — CURRENT DEPLOYED STATE

Last updated: April 6, 2026

This document is the source of truth for the current deployed state. It supersedes the original BLUEPRINT.md where the two conflict.

---

## DEPLOYED PROGRAM

- **Program ID:** `GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU`
- **Cluster:** Devnet
- **Binary size:** 451 KB
- **IDL account:** `Ga5PRgbVxhh9ek39BRHCXgsb5obHqYooq4qV2ebJ8tKG` (v0.2.0, obfuscated field names)
- **Vault PDA:** `3ioMEKQvKnLaR8JFQUgsNFDby9Xi89M5MWZXNzdUJZoG`
- **Merkle Tree PDA:** `2rvpifNShofeGz1BqJHeVPHoyvm43fYpcU5vtgozLrA2`
- **Treasury PDA:** `1427qYPVC3ghVifCtg45yDtoSvdzNKQ3TEce5kK3c6Wr` (program-owned, direct lamport manipulation)
- **SOL Vault PDA (legacy):** `98JeSWAaTKaAKBecyj6Wttme4CKvEUGy1wHiqVX1H3oE` (orphaned, ~0.2 SOL stuck)
- **Payer wallet:** `rStMSBkdd56LNws9iEu8DLw7xGRrtCy6YA2KemcBPHm`

### Vault state

- Merkle tree: 22 leaves inserted (18 legacy + 4 credit note tests)
- Legacy stuck funds: ~0.2 SOL in old sol_vault PDA (system-owned, orphaned after treasury migration)
- Drop cap: 100 SOL

### Proof TX signatures (devnet, verifiable on Solscan)

| TX | Type | What to verify |
|----|------|----------------|
| `5UoxWisVP7cYJ485MS8egNeHnM2G8C8nqTEAUjsdgc3r5aViQLXXagL3UzFjqSnaLZDwnthRAXMXvheh1Z9VPXf7` | create_drop | CPI Transfer inner instruction visible (deposit amount visible — expected) |
| `4dFoynPNF8RA88YZbS5ZoZB13GdLxab8223DnGArQqiV2BnU3ZQEENdDqL6SEFBwpQA652kiU8useWRU7gYMoJAD` | claim_credit | Zero amounts in instruction data. Only PDA creation inner instructions. Treasury balance unchanged. |
| `2bvjTdBZfCozGMEhiWRHtgdakDGy3eQtx4SVuaNDU3ahEi1SzMU9S1NT3qkiPwbX8RB8msoRfY8Uf459w4eTxd4o` | withdraw_credit | Zero inner instructions. Balance deltas in account list but no decoded "Transfer X SOL". |

---

## CREDIT NOTE ARCHITECTURE (V2)

This is DarkDrop's core privacy innovation, deployed April 6, 2026. The claim is split into two steps: `claim_credit` (amount hidden) and `withdraw_credit` (amount revealed but decorrelated from deposit).

### How it works

```
DEPOSIT (create_drop):
  User sends SOL to treasury via CPI.
  Leaf inserted into Merkle tree.
  Amount visible in CPI inner instruction — same as any SOL transfer.

CLAIM (claim_credit):
  ZK proof verified (V2 circuit — amount is PRIVATE, not a public input).
  CreditNote PDA created storing Poseidon(amount, blinding_factor).
  Nullifier marked spent.
  ZERO SOL moves. ZERO amount in instruction data.
  Observer sees: opaque proof bytes, opaque input bytes, PDA creation. Nothing else.

WITHDRAW (withdraw_credit):
  User opens the commitment (reveals amount + blinding_factor).
  Program recomputes Poseidon on-chain and verifies.
  SOL transferred via DIRECT LAMPORT MANIPULATION — not system_program::transfer.
  No CPI. No inner instruction. No decoded "Transfer" on any explorer.
  Fee computed from basis points rate, not a plaintext lamport parameter.
  CreditNote PDA closed.
```

### Why this matters

The claim TX is the on-chain event that connects a deposit to a withdrawal. In the credit note model, this TX contains **zero amount information** and **zero SOL movement**. An observer who finds the claim TX on-chain sees:

- A Groth16 proof (opaque 256 bytes)
- An `inputs` blob (opaque 96 bytes — no field labeled "amount")
- A `nullifier_hash` (meaningless without the original secret)
- Two PDA creations (CreditNote + Nullifier — standard Anchor `init`)

They cannot determine how much SOL was deposited, how much will be withdrawn, or which deposit this claim corresponds to.

The withdrawal is a separate TX from a potentially different wallet at a potentially different time. It shows balance deltas in the account list but no decoded `Transfer` instruction because direct lamport manipulation does not invoke `system_program::transfer`.

### What's visible vs hidden

| Data point | Deposit TX | Claim TX | Withdraw TX |
|---|---|---|---|
| Sender wallet | Visible | Not present | Not present |
| Receiver wallet | Not present | Present (as recipient account) | Present |
| Amount | Visible (CPI transfer) | **HIDDEN** | Balance delta only (not decoded) |
| Link deposit→claim | Impossible (Merkle proof hides which leaf) | — | — |
| Link claim→withdraw | Same nullifier_hash in CreditNote PDA | — | CreditNote PDA closed |
| Inner instructions | system_program Transfer | system_program CreateAccount (PDAs only) | **NONE** |

### Dual circuit / dual verification key

The program stores two Groth16 verification keys:

- **V1** (6 public inputs, amount is public): Used by the legacy `claim` instruction for backward compatibility with proofs generated before the V2 upgrade.
- **V2** (5 public inputs, amount is private): Used by `claim_credit`. Same circuit constraints — only the public/private boundary changed.

Both circuits have 5,946 constraints and use the same Poseidon, Merkle, range check, and password constraints.

### Treasury PDA (program-owned)

The treasury at `[b"treasury"]` is owned by the DarkDrop program (not the system program). This enables direct lamport manipulation:

```rust
// Debit treasury (program-owned — our program can decrease its lamports)
**treasury.to_account_info().try_borrow_mut_lamports()? -= amount;
// Credit recipient (any program can increase any account's lamports)
**recipient.to_account_info().try_borrow_mut_lamports()? += recipient_amount;
```

This produces zero CPI calls and zero inner instructions. `system_program::transfer` CAN send SOL TO the treasury (for deposits) because the `to` account's ownership is not checked by the system program.

### IDL obfuscation

The IDL (v0.2.0) uses deliberately uninformative field names:

| Actual meaning | IDL field name | Why |
|---|---|---|
| amount (create_drop) | `data` | Prevents Solscan from labeling it "Amount: 100,000,000" |
| amount_commitment | `commitment` | Generic |
| password_hash | `seed` | Generic |
| fee_lamports (legacy claim) | `params` | Generic |
| amount + blinding (withdraw) | `opening` | Opaque bytes, no sub-fields |
| fee rate (withdraw) | `rate` | u16, not decoded as lamports |

No field in any instruction is named "amount", "lamports", "fee", or "balance".

---

## ARCHITECTURE CHANGES FROM BLUEPRINT

### 1. Poseidon everywhere, no Pedersen

**Blueprint said:** Amount commitment uses Pedersen commitment (`Pedersen(amount, blinding_factor)`).

**What was built:** Amount commitment uses Poseidon hash (`Poseidon(amount, blinding_factor)`). Pedersen commitments were never implemented. The circuit, program, and client all use Poseidon for everything:

- Leaf: `Poseidon(secret, nullifier, amount, blinding_factor)`
- Nullifier hash: `Poseidon(nullifier)`
- Amount commitment: `Poseidon(amount, blinding_factor)`
- Password hash: `Poseidon(password)`
- Recipient field: `Poseidon(pubkey_hi_128, pubkey_lo_128)`

**Why:** Poseidon is ZK-friendly with low constraint count. Pedersen commitments would have required elliptic curve operations inside the circuit (cross-curve problem on BN254 — ~150K extra constraints). Poseidon commitment is computationally hiding and binding, and keeps the circuit at 5,946 constraints.

### 2. Public input order

snarkjs assigns public signal indices by declaration order in the circuit template, not by the order in `component main {public [...]}`.

**V1 circuit (legacy, 6 public inputs):**
```
[0] amount, [1] merkle_root, [2] nullifier_hash, [3] recipient, [4] amount_commitment, [5] password_hash
```

**V2 circuit (credit note, 5 public inputs — amount is PRIVATE):**
```
[0] merkle_root, [1] nullifier_hash, [2] recipient, [3] amount_commitment, [4] password_hash
```

### 3. Recipient is Poseidon-hashed, not raw pubkey

Raw Solana pubkeys are 256 bits but the BN254 scalar field is ~254 bits. A raw pubkey can exceed the field modulus. Instead:

```
recipient_field = Poseidon(pubkey_hi_128, pubkey_lo_128)
```

### 4. Proof A must be negated (BN254 G1)

`groth16-solana` expects `proof_a` with the y-coordinate negated: `proof_a.y = BN254_Fq - proof_a.y`.

### 5. G2 point encoding — element pairs reversed

```
snarkjs: [[x0, x1], [y0, y1]]
on-chain: [x1, x0, y1, y0]  (each 32 bytes BE)
```

### 6. Nullifier PDA instead of registry account

Each nullifier gets its own PDA: `seeds = [b"nullifier", nullifier_hash]`. Anchor's `init` constraint gives double-spend prevention for free.

### 7. Triple verification keys compiled into the program

V1, V2, and V3 VKs are compiled into `vk.rs` as constants. `verifying_key_v1()` for legacy `claim`, `verifying_key_v2()` for `claim_credit`, `verifying_key_v3()` for `claim_from_note_pool`.

### 8. Root history — fixed-size circular buffer

30 recent roots stored. After 30 new drops, old roots expire.

### 9. Fee system

- Legacy `claim`: `fee_lamports: u64` parameter (explicit lamport value)
- `withdraw_credit`: `rate: u16` parameter (basis points). Fee = `amount * rate / 10000`.

### 10. Relayer is sole signer on gasless claims

Recipient never signs. Only `payer` signs. ZK proof binds to recipient via `Poseidon(pubkey)`.

### 11. Credit note model for hidden amounts

See "CREDIT NOTE ARCHITECTURE (V2)" section above. This replaces the earlier "amounts are visible" architectural note. Amounts ARE visible at deposit time (CPI transfer), but the claim TX contains zero amount information, and the withdraw TX uses direct lamport manipulation with no inner instructions.

### 12. Admin sweep with obligation tracking

`admin_sweep` transfers excess SOL from treasury to authority. Sweep is limited to `treasury_balance - (total_deposited - total_withdrawn) - rent_exempt_min`, preventing the authority from sweeping funds belonging to outstanding credit notes. Emits a `TreasurySweep` event.

### 13. Note Pool — second-layer Merkle mixer for credit notes

The Note Pool provides recursive privacy: the first ZK proof (V2, `claim_credit`) hides which deposit was claimed. The second ZK proof (V3, `claim_from_note_pool`) hides which credit note is being redeemed. An observer must break BOTH layers to deanonymize a user.

#### How it works

```
CREDIT NOTE (from Layer 1):
  User has a CreditNote PDA from claim_credit.
  Contains: re-randomized commitment Poseidon(Poseidon(amount, blinding), salt).

DEPOSIT TO POOL (deposit_to_note_pool):
  User opens the credit note commitment (reveals amount + blinding + salt to the program).
  Program VERIFIES the opening: Poseidon(Poseidon(amount, blinding), salt) == stored_commitment.
  Program constructs pool_leaf ON-CHAIN: Poseidon(pool_secret, pool_nullifier, VERIFIED_amount, pool_blinding).
  Pool leaf inserted into NotePoolTree Merkle tree.
  Old CreditNote PDA closed. Zero SOL moves.

  KEY SECURITY PROPERTY: The program constructs the leaf using the verified amount.
  The user cannot lie about the amount. This eliminates the dishonest leaf problem (I-01)
  that exists in the base DarkDrop layer where create_drop trusts user-provided leaves.

CLAIM FROM POOL (claim_from_note_pool):
  User generates a V3 Groth16 proof proving:
    1. They know the preimage of a leaf in the NotePoolTree
    2. The pool nullifier matches the declared hash
    3. A new credit note commitment encodes the SAME amount with fresh randomness
    4. The proof is bound to a specific recipient
  Program verifies the proof and creates a FRESH CreditNote PDA.
  Pool nullifier PDA created (prevents double-claim).
  Zero SOL moves. No amounts visible.

WITHDRAW (withdraw_credit — same as before):
  User withdraws from the fresh credit note.
  The fresh commitment is completely unlinkable to the original.
```

#### What an observer sees

| Step | On-chain footprint | Amount visible? | Linkable to deposit? |
|------|-------------------|-----------------|---------------------|
| Deposit (create_drop) | CPI Transfer | Yes | — |
| Claim (claim_credit) | Proof + PDA creation | No | No (ZK proof hides leaf) |
| Pool deposit | PDA close + tree insert | No | No (commitment opened privately) |
| Pool claim | Proof + new PDA creation | No | No (ZK proof hides pool leaf) |
| Withdraw (withdraw_credit) | Lamport manipulation | Yes (balance delta) | No (double decorrelation) |

#### V3 Circuit (NotePoolClaimProof)

- **File:** `circuits/note_pool.circom`
- **Constraints:** 6,210
- **Public inputs:** 4 (`pool_merkle_root`, `pool_nullifier_hash`, `new_stored_commitment`, `recipient_hash`)
- **Private inputs:** 10 (`pool_secret`, `pool_nullifier`, `amount`, `pool_blinding_factor`, `pool_path[20]`, `pool_indices[20]`, `new_blinding`, `new_salt`, `recipient_hi`, `recipient_lo`)
- **Proving system:** Groth16 (BN254), same Powers of Tau as V1/V2
- **WASM:** `circuits/build/note_pool/note_pool_js/note_pool.wasm` (2.5 MB)
- **Proving key:** `circuits/build/note_pool/note_pool_final.zkey` (5.8 MB)

#### New on-chain state

- **NotePool PDA** `[b"note_pool"]`: bump, total_deposits, total_claims
- **NotePoolTree PDA** `[b"note_pool_tree", vault]`: Same structure as MerkleTreeAccount (filled_subtrees, root_history, next_index). Depth 20, supports 2^20 pool entries.
- **PoolNullifierAccount PDA** `[b"pool_nullifier", hash]`: Prevents double-claim from pool. Separate namespace from base nullifiers.

#### New instructions

| Instruction | Accounts | Args | Effect |
|-------------|----------|------|--------|
| `initialize_note_pool` | vault, note_pool, note_pool_tree, authority, system_program | none | Creates NotePool + NotePoolTree PDAs. Authority only. |
| `deposit_to_note_pool` | vault, note_pool, note_pool_tree, credit_note, recipient, payer, system_program | nullifier_hash, opening (72 bytes), pool_params (96 bytes) | Opens credit note, constructs pool leaf with verified amount, inserts into pool tree, closes credit note. |
| `claim_from_note_pool` | vault, note_pool, note_pool_tree, credit_note, pool_nullifier, recipient, payer, system_program | pool_nullifier_hash, proof (ProofData), inputs (64 bytes) | Verifies V3 proof, creates fresh CreditNote PDA, creates pool nullifier PDA. |

---

## CIRCUITS

### V1 circuit (legacy)

- **Public inputs:** 6 (amount, merkle_root, nullifier_hash, recipient, amount_commitment, password_hash)
- **Proving key:** `circuits/build/darkdrop_final.zkey` (5.4 MB)
- **Status:** Supported for backward compatibility via legacy `claim` instruction

### V2 circuit (credit note)

- **File:** `circuits/darkdrop.circom`
- **Constraints:** 5,946 (unchanged from V1)
- **Public inputs:** 5 (merkle_root, nullifier_hash, recipient, amount_commitment, password_hash)
- **Private inputs:** amount (was public in V1), secret, nullifier, blinding_factor, password, merkle_path[20], merkle_indices[20]
- **Merkle depth:** 20 (supports 2^20 = 1,048,576 drops)
- **Hash function:** Poseidon (for all commitments)
- **Proving system:** Groth16 (BN254)
- **Trusted setup:** Powers of Tau (pot14), circuit-specific phase 2
- **WASM:** `circuits/build/darkdrop_js/darkdrop.wasm` (2.5 MB)
- **Proving key:** `circuits/build/darkdrop_v2_final.zkey` (5.4 MB)
- **Verification key:** `circuits/build/verification_key_v2.json`
- **Circuit test results:** 11/11 passing

### V3 circuit (note pool)

- **File:** `circuits/note_pool.circom`
- **Constraints:** 6,210
- **Public inputs:** 4 (pool_merkle_root, pool_nullifier_hash, new_stored_commitment, recipient_hash)
- **Private inputs:** pool_secret, pool_nullifier, amount, pool_blinding_factor, pool_path[20], pool_indices[20], new_blinding, new_salt, recipient_hi, recipient_lo
- **Merkle depth:** 20 (supports 2^20 = 1,048,576 pool entries)
- **Hash function:** Poseidon (Poseidon(4) for pool leaf, Poseidon(2) for Merkle/commitments)
- **Proving system:** Groth16 (BN254)
- **Trusted setup:** Powers of Tau (pot14), circuit-specific phase 2
- **WASM:** `circuits/build/note_pool/note_pool_js/note_pool.wasm` (2.5 MB)
- **Proving key:** `circuits/build/note_pool/note_pool_final.zkey` (5.8 MB)
- **Verification key:** `circuits/build/note_pool/verification_key_note_pool.json`

---

## PROGRAM INSTRUCTIONS

### initialize_vault

```
Discriminator: [48, 191, 163, 44, 71, 129, 63, 164]
Args: drop_cap (u64)
Accounts: vault, merkle_tree, treasury, authority, system_program
```

Creates the vault, Merkle tree, and program-owned treasury PDA. Called once on fresh deployments.

### create_treasury (migration)

```
Args: none
Accounts: vault, treasury, authority, system_program
```

One-time migration: creates the Treasury PDA on existing deployments where vault/merkle_tree already exist. Only callable by vault authority.

### create_drop

```
Discriminator: [157, 142, 145, 247, 92, 73, 59, 48]
Args: leaf ([u8;32]), amount (u64), amount_commitment ([u8;32]), password_hash ([u8;32])
Accounts: vault, merkle_tree, treasury, sender, system_program
```

Validates amount (> 0, <= drop_cap), transfers SOL from sender to treasury via CPI, inserts leaf into Merkle tree, emits `DropCreated` event.

### claim (legacy — V1 circuit)

```
Discriminator: [62, 198, 214, 193, 213, 159, 108, 210]
Args: proof (ProofData), merkle_root ([u8;32]), nullifier_hash ([u8;32]),
      amount (u64), amount_commitment ([u8;32]), password_hash ([u8;32]),
      fee_lamports (u64)
Accounts: vault, merkle_tree, treasury, nullifier_account, recipient,
          fee_recipient, payer, system_program
```

Uses V1 verification key (6 public inputs). Transfers SOL via direct lamport manipulation from treasury. Kept for backward compatibility.

### claim_credit (V2 circuit — hidden amount)

```
Discriminator: [190, 242, 172, 79, 29, 82, 22, 163]
Args: nullifier_hash ([u8;32]), proof (ProofData), inputs (Vec<u8> — 96 bytes opaque)
Accounts: vault, merkle_tree, credit_note, nullifier_account, recipient, payer, system_program
```

Verifies Groth16 proof using V2 circuit (5 public inputs, amount is PRIVATE). Creates CreditNote PDA storing the Poseidon commitment. Marks nullifier spent. **ZERO SOL moves.** No amount anywhere in instruction data or events.

The `inputs` field is an opaque 96-byte blob: `merkle_root(32) + amount_commitment(32) + password_hash(32)`.

| Index | Account | Writable | Signer |
|-------|---------|----------|--------|
| 0 | vault | yes | no |
| 1 | merkle_tree | no | no |
| 2 | credit_note | yes | no |
| 3 | nullifier_account | yes | no |
| 4 | recipient | no | no |
| 5 | payer | yes | yes |
| 6 | system_program | no | no |

### withdraw_credit (direct lamport manipulation)

```
Discriminator: [8, 173, 134, 129, 40, 255, 134, 30]
Args: nullifier_hash ([u8;32]), opening (Vec<u8> — 40 bytes opaque), rate (u16)
Accounts: vault, treasury, credit_note, recipient, fee_recipient, payer, system_program
```

Opens the Poseidon commitment. Program recomputes `Poseidon(amount, blinding_factor)` on-chain and verifies against stored commitment. Transfers SOL via direct lamport manipulation — no CPI, no inner instruction. Fee = `amount * rate / 10000`. CreditNote PDA closed after withdrawal.

The `opening` field is an opaque 40-byte blob: `amount(8 LE) + blinding_factor(32)`.

| Index | Account | Writable | Signer |
|-------|---------|----------|--------|
| 0 | vault | no | no |
| 1 | treasury | yes | no |
| 2 | credit_note | yes | no |
| 3 | recipient | yes | no |
| 4 | fee_recipient | yes | no |
| 5 | payer | yes | yes |
| 6 | system_program | no | no |

### ProofData struct

```rust
pub struct ProofData {
    pub proof_a: [u8; 64],   // G1 point, y-coordinate NEGATED
    pub proof_b: [u8; 128],  // G2 point, element pairs reversed
    pub proof_c: [u8; 64],   // G1 point, standard encoding
}
```

### CreditNote struct

```rust
pub struct CreditNote {
    pub bump: u8,
    pub recipient: Pubkey,
    pub commitment: [u8; 32],      // Poseidon(amount, blinding_factor)
    pub nullifier_hash: [u8; 32],
    pub created_at: i64,
}
// PDA seeds: [b"credit", nullifier_hash]
// Size: 113 bytes, rent ~0.00157 SOL (returned on close)
```

### Error codes

| Code | Name | Description |
|------|------|-------------|
| 6000 | TreeFull | Merkle tree has 2^20 leaves |
| 6001 | InvalidRoot | Merkle root not in 30-root history |
| 6002 | NullifierAlreadySpent | Nullifier PDA already exists |
| 6003 | InvalidProof | Groth16 verification failed |
| 6004 | AmountExceedsCap | Amount > drop_cap |
| 6005 | ZeroAmount | Amount = 0 |
| 6006 | Overflow | Arithmetic overflow |
| 6007 | InsufficientBalance | Treasury doesn't have enough SOL |
| 6008 | FeeTooHigh | fee >= amount |
| 6009 | CommitmentMismatch | Poseidon(amount, blinding) != stored commitment |
| 6010 | UnauthorizedWithdraw | Recipient doesn't match CreditNote |
| 6011 | InvalidInputLength | Opaque inputs/opening wrong size |

---

## TEST RESULTS

### Credit Note E2E Test (devnet)

Script: `scripts/e2e-credit-test.js`. Run with `RPC_URL=https://api.devnet.solana.com`.

| Step | Result | Detail |
|------|--------|--------|
| create_drop | PASS | Treasury balance +100,000,000 lamports |
| V2 proof generation | PASS | 5 public signals, local verification passed |
| claim_credit | PASS | Treasury unchanged, credit note created, nullifier spent |
| claim_credit inner instructions | PASS | No Transfer inner instruction (only CreateAccount for PDAs) |
| withdraw_credit | PASS | Recipient +100,000,000 lamports, credit note closed |
| withdraw_credit inner instructions | PASS | **0 inner instructions** (direct lamport manipulation) |

### Credit Note Security Tests (devnet)

Script: `scripts/security-credit-tests.js`. All 7/7 passing.

| Test | Attack Vector | Status | Error |
|------|--------------|--------|-------|
| Double-withdraw | withdraw_credit twice with same nullifier | PASS | CreditNote PDA closed after first withdrawal |
| Wrong amount | withdraw_credit with amount + 1000 | PASS | CommitmentMismatch |
| Wrong blinding factor | withdraw_credit with random blinding | PASS | CommitmentMismatch |
| Wrong recipient | withdraw_credit to different wallet | PASS | UnauthorizedWithdraw |
| Fake credit note | withdraw_credit without claim_credit | PASS | CreditNote PDA doesn't exist |
| Amount tampering | withdraw_credit with 1 SOL instead of 0.05 | PASS | CommitmentMismatch |
| Replay claim_credit | claim_credit with same nullifier twice | PASS | Nullifier PDA already exists |

### Legacy Security Tests (localnet)

Script: `scripts/security-tests.js`. 6/6 passing (unchanged from V1).

| Test | Status | Mechanism |
|------|--------|-----------|
| Double-claim (reuse nullifier) | PASS | Nullifier PDA init fails |
| Invalid proof (garbage bytes) | PASS | InvalidProof error |
| Wrong password | PASS | Circuit constraint failure |
| Wrong recipient (proof for A, claim as B) | PASS | InvalidProof |
| Amount tampering (proof for 0.05, claim 1.0) | PASS | InvalidProof |
| Exhausted root (31 drops to push root out) | PASS | InvalidRoot error |

### Relayer Test

Script: `scripts/relayer-test.js`.

| Check | Result |
|-------|--------|
| Recipient received correct net amount | 0.0995 SOL (0.1 - 0.5% fee) |
| Fee deducted correctly | 0.0005 SOL (0.5%) |
| Recipient is TX signer | **false** |
| Recipient is TX fee payer | **false** |

---

## CLAIM CODE FORMAT

```
darkdrop:v4:{cluster}:{asset}:{encryption}:{payload}
```

### Payload (JSON, then base64url)

```json
{
  "s": "base58_secret",
  "n": "base58_nullifier",
  "a": "amount_lamports_string",
  "b": "base58_blinding_factor",
  "i": leaf_index,
  "v": "base58_vault_address"
}
```

### Encryption

- `raw`: base64url-encoded JSON, anyone with code can claim
- `aes:{hint}:{payload}`: AES-256-GCM encrypted, password required

---

## RELAYER

### Architecture

Express.js server. Source: `relayer/src/`. Build on Linux fs at `~/darkdrop-v4-relayer`.

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Status + relayer pubkey |
| `POST /api/relay/claim` | Legacy claim relay (V1 circuit) |
| `POST /api/relay/create-drop` | Deposit relay — user sends SOL to relayer, relayer calls create_drop |
| `POST /api/relay/credit/claim` | Credit note claim relay (V2 circuit) |
| `POST /api/relay/credit/withdraw` | Credit note withdraw relay |

### Deposit relay flow

1. User sends SOL to relayer wallet via normal `system_program::transfer` (separate TX, looks like any wallet-to-wallet send)
2. User calls `POST /api/relay/create-drop` with the deposit TX signature
3. Relayer verifies the TX transferred enough SOL, then calls `create_drop` with itself as sender
4. User's wallet never appears in any DarkDrop transaction

### Configuration

| Setting | Default | Env var |
|---------|---------|---------|
| RPC URL | devnet | RPC_URL |
| Fee | 50 bps (0.5%) | FEE_RATE_BPS |
| Port | 3001 | PORT |
| Max claim | 100 SOL | MAX_CLAIM |
| Rate limit | 10 req/min/IP | — |
| Keypair | ~/.config/solana/relayer.json | RELAYER_KEYPAIR |

### Trust model

The relayer cannot steal funds (ZK proof binds to recipient). The relayer can only:
- Refuse to relay (censorship) — mitigated by direct claim/deposit fallback
- See the recipient's IP — mitigated by VPN/Tor
- See the deposit amount (for deposit relay) — same as any block observer

---

## FRONTEND

### Tech stack

- Next.js 16.2.2 (Turbopack)
- React 19.2.4
- Tailwind CSS 4
- Fira Code font
- Wallet adapter: Phantom + Solflare
- ZK proofs: snarkjs WASM (client-side, V2 circuit)
- Cluster: devnet (hardcoded in WalletProvider)

### Pages

| Route | Status | Description |
|-------|--------|-------------|
| / | Built | Landing page with honest privacy model |
| /drop/create | Wired to devnet | Direct deposit or Private Deposit (via relayer) |
| /drop/claim | Wired to devnet | Two-TX flow: claim_credit + withdraw_credit, gasless/direct toggle |

### Claim flow (two TXs, one button)

1. User pastes claim code, selects gasless or direct
2. Browser generates V2 Groth16 proof (amount is private)
3. TX 1: `claim_credit` — proof verified, credit note created, zero SOL moves
4. TX 2: `withdraw_credit` — commitment opened, SOL transferred via direct lamport manipulation
5. User sees single "Claimed X SOL" result

### Build

Source: `/mnt/d/darkdrop-v4/frontend/`. Build from Linux fs: `~/darkdrop-v4-frontend`.

```bash
cd ~/darkdrop-v4-frontend
npx next build     # production build
npx next dev       # dev server
```

Circuit artifacts in `public/circuits/`:
- `darkdrop.wasm` (2.5 MB)
- `darkdrop_final.zkey` (5.4 MB) — V1 legacy
- `darkdrop_v2_final.zkey` (5.4 MB) — V2 credit note

### Instruction discriminators (hardcoded in frontend)

```
create_drop:     [157, 142, 145, 247, 92, 73, 59, 48]
claim_credit:    [190, 242, 172, 79, 29, 82, 22, 163]
withdraw_credit: [8, 173, 134, 129, 40, 255, 134, 30]
```

---

## FILE LOCATIONS

### Program

| File | Purpose |
|------|---------|
| `program/programs/darkdrop/src/lib.rs` | Entry point, 10 instruction routing |
| `program/programs/darkdrop/src/state.rs` | Vault, Treasury, CreditNote, MerkleTreeAccount, NullifierAccount, NotePool, NotePoolTree, PoolNullifierAccount, ProofData |
| `program/programs/darkdrop/src/instructions/initialize.rs` | initialize_vault (creates vault + merkle_tree + treasury) |
| `program/programs/darkdrop/src/instructions/create_drop.rs` | create_drop (CPI to treasury) |
| `program/programs/darkdrop/src/instructions/claim.rs` | Legacy claim (V1 VK, direct lamport manipulation) |
| `program/programs/darkdrop/src/instructions/claim_credit.rs` | claim_credit (V2 VK, zero SOL movement) |
| `program/programs/darkdrop/src/instructions/withdraw_credit.rs` | withdraw_credit (Poseidon verification, direct lamport manipulation) |
| `program/programs/darkdrop/src/instructions/create_treasury.rs` | One-time migration |
| `program/programs/darkdrop/src/instructions/admin_sweep.rs` | admin_sweep (treasury sweep with obligation tracking) |
| `program/programs/darkdrop/src/instructions/initialize_note_pool.rs` | initialize_note_pool (creates pool + pool tree) |
| `program/programs/darkdrop/src/instructions/deposit_to_note_pool.rs` | deposit_to_note_pool (opens credit note, constructs pool leaf) |
| `program/programs/darkdrop/src/instructions/claim_from_note_pool.rs` | claim_from_note_pool (V3 proof, fresh credit note) |
| `program/programs/darkdrop/src/errors.rs` | DarkDropError enum (12 variants) |
| `program/programs/darkdrop/src/verifier.rs` | verify_proof (V1) + verify_proof_v2 (V2) + verify_proof_v3 (V3) |
| `program/programs/darkdrop/src/vk.rs` | Triple VK: verifying_key_v1() + verifying_key_v2() + verifying_key_v3() |
| `program/programs/darkdrop/src/poseidon.rs` | On-chain Poseidon hash (light-hasher, 2-input + 4-input) |
| `program/programs/darkdrop/src/merkle_tree.rs` | Merkle tree append (main tree + note pool tree) |
| `program/idl/darkdrop.json` | Hand-written IDL v0.3.0 (obfuscated names) |
| `program/target/deploy/darkdrop.so` | Compiled program binary (451 KB) |

### Circuits

| File | Purpose |
|------|---------|
| `circuits/darkdrop.circom` | V2 claim circuit (amount private) |
| `circuits/note_pool.circom` | V3 note pool circuit (recursive privacy) |
| `circuits/build/darkdrop_js/darkdrop.wasm` | WASM prover (2.5 MB, shared V1/V2) |
| `circuits/build/darkdrop_final.zkey` | V1 proving key (5.4 MB) |
| `circuits/build/darkdrop_v2_final.zkey` | V2 proving key (5.4 MB) |
| `circuits/build/verification_key.json` | V1 verification key |
| `circuits/build/verification_key_v2.json` | V2 verification key |
| `circuits/build/note_pool/note_pool_js/note_pool.wasm` | V3 WASM prover (2.5 MB) |
| `circuits/build/note_pool/note_pool_final.zkey` | V3 proving key (5.8 MB) |
| `circuits/build/note_pool/verification_key_note_pool.json` | V3 verification key |

### Scripts

| File | Purpose |
|------|---------|
| `scripts/e2e-test.js` | Legacy E2E test (V1 circuit) |
| `scripts/e2e-credit-test.js` | Credit note E2E test (V2 circuit) |
| `scripts/security-tests.js` | 6 legacy security tests |
| `scripts/security-credit-tests.js` | 7 credit note security tests |
| `scripts/relayer-test.js` | Relayer gasless claim E2E test |
| `scripts/note-pool-test.js` | Note pool E2E test (recursive privacy flow) |
| `scripts/note-pool-security-tests.js` | 4 note pool security tests |
| `scripts/export_vk_rust.js` | Convert verification_key.json to Rust constants |

### Relayer

| File | Purpose |
|------|---------|
| `relayer/src/index.ts` | Express server, routes, health check |
| `relayer/src/config.ts` | Configuration |
| `relayer/src/routes/claim.ts` | Legacy claim relay |
| `relayer/src/routes/deposit.ts` | Deposit relay (private deposit) |
| `relayer/src/routes/credit.ts` | Credit claim + withdraw relay |

---

## BUILD TOOLCHAIN

### Anchor build workaround

`anchor build` fails. Use:

```bash
cd program
cargo build-sbf
cp target/sbpf-solana-solana/release/darkdrop.so target/deploy/darkdrop.so
```

### IDL management

IDL is hand-written with obfuscated field names. After changes:

```bash
anchor idl upgrade GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU \
  --filepath idl/darkdrop.json \
  --provider.cluster devnet \
  --provider.wallet ~/.config/solana/id.json
```

### Versions

| Tool | Version |
|------|---------|
| Anchor CLI | 0.30.1 |
| Rust | 1.87.0 (stable) |
| Solana CLI | cargo-build-sbf via 1.84.1-sbpf toolchain |
| Circom | v2.2.2 |
| Node.js | v20 |
| Next.js | 16.2.2 |

---

## KNOWN ISSUES

1. **~0.2 SOL stuck in legacy sol_vault.** Orphaned after treasury migration. No admin_sweep instruction.

2. **No revoke instruction.** Depositors cannot reclaim funds from unclaimed drops.

3. **Anonymity set is small.** Vault has ~22 leaves on devnet. Need to self-seed with diverse amounts.

4. **No SPL token support.** Only SOL.

5. **`anchor build` broken.** Must use `cargo build-sbf`. IDL hand-written.

6. **No QR codes, burn links, or history page.** Core flow only.

7. **Deposit amount still visible.** The `create_drop` CPI transfer reveals the deposit amount. This is fundamental — SOL must physically move. The credit note model hides the amount at claim time and decorrelates it at withdraw time, but the deposit itself is public.

8. **Relayer not on public VPS.** Running locally only. Needs deployment for production use.

---

## WHAT DARKDROP ACHIEVES

- Sender and receiver wallets are **never linked on-chain**
- The claim TX contains **zero decoded amounts** and **zero SOL movement**
- The withdraw TX contains **zero inner instructions** (direct lamport manipulation)
- The receiver **never signs** any transaction (gasless relay)
- The IDL reveals **no amount-related field names** to block explorers
- Double-spend prevention via **nullifier PDAs**
- ZK proof correctness verified on-chain via **Groth16 on BN254**
- Commitment binding via **Poseidon hash** (computationally hiding + binding)
- Commitment re-randomization via **salt** (on-chain commitments cannot be matched to deposit data)
- **Recursive privacy** via Note Pool (second-layer Merkle mixer for credit notes)
- **Dishonest leaf elimination** at pool layer (program constructs pool leaves with verified amounts)

---

*End of current state document.*
