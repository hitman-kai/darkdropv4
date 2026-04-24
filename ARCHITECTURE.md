# DARKDROP V4 — CURRENT DEPLOYED STATE

Last updated: April 23, 2026

This document is the source of truth for the current deployed state. It supersedes the original BLUEPRINT.md where the two conflict.

---

## DEPLOYED PROGRAM

- **Program ID:** `GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU`
- **Cluster:** Devnet
- **Binary size:** 667 KB (683,096 bytes)
- **Latest upgrade TX:** `2rPAbEi7reBnkjQPak6KmKbZyoSJnswbjTQGtvSaCiewfBsN5aNRwX2mJMxrRUXaRUHLXB3LyBpxH6c5mPB7DV1V` (create_drop_to_pool, 2026-04-23)
- **Schema v2 migration TX:** `qUSWwGLfdm28TP12BRJwAvcDRVx5U75GfXdte8x5MPK3K56qNvm8jKn52qFBWQwzmz3dmHkR4NWtBduc8VXjsX3` (MerkleTree + NotePoolTree reallocated to ROOT_HISTORY_SIZE=256, 2026-04-23)
- **IDL account:** `Ga5PRgbVxhh9ek39BRHCXgsb5obHqYooq4qV2ebJ8tKG` (v0.3.0, obfuscated field names; see KNOWN ISSUES — IDL declares 13 instructions, binary exposes 18)
- **Vault PDA:** `3ioMEKQvKnLaR8JFQUgsNFDby9Xi89M5MWZXNzdUJZoG`
- **Merkle Tree PDA:** `2rvpifNShofeGz1BqJHeVPHoyvm43fYpcU5vtgozLrA2`
- **Treasury PDA:** `1427qYPVC3ghVifCtg45yDtoSvdzNKQ3TEce5kK3c6Wr` (program-owned, direct lamport manipulation)
- **SOL Vault PDA (legacy):** `98JeSWAaTKaAKBecyj6Wttme4CKvEUGy1wHiqVX1H3oE` (orphaned, ~0.2 SOL stuck)
- **Payer wallet:** `rStMSBkdd56LNws9iEu8DLw7xGRrtCy6YA2KemcBPHm`

### Vault state

- Merkle tree: ~230+ leaves (grows continuously via seeder, ~15–30 drops/day)
- MerkleTree + NotePoolTree accounts: 8912 bytes each (schema v2, ROOT_HISTORY_SIZE=256)
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

The IDL (v0.3.0) uses deliberately uninformative field names:

| Actual meaning | IDL field name | Why |
|---|---|---|
| amount (create_drop) | `data` | Prevents Solscan from labeling it "Amount: 100,000,000" |
| amount (create_drop_to_pool) | `data` | Same obfuscation as create_drop |
| amount_commitment | `commitment` | Generic |
| password_hash | `seed` | Generic |
| fee_lamports (legacy claim) | `params` | Generic |
| amount + blinding + salt (withdraw) | `opening` | Opaque 72-byte blob, no sub-fields |
| fee rate (withdraw) | `rate` | u16, not decoded as lamports |
| pool_secret + pool_nullifier + pool_blinding | `params` | Opaque 96-byte blob for both deposit_to_note_pool and create_drop_to_pool |

No field in any instruction is named "amount", "lamports", "fee", or "balance".

---

## REVOKE INSTRUCTION (deployed April 20, 2026)

### Problem

If a user loses their claim code, the SOL sits in the treasury forever with no recovery path. On devnet this is cosmetic — on mainnet it's the biggest foot-gun in the protocol. The depositor needs a fallback path to reclaim unclaimed drops without breaking the anonymity guarantees for drops that ARE claimed.

### Design

At deposit time, the depositor (optionally) allocates a `DepositReceipt` PDA seeded by the leaf. The receipt records `depositor`, `amount`, `leaf`, and `created_at`. Rent is paid by the depositor so they (not the sender/relayer) own it.

After `REVOKE_TIMEOUT` seconds have elapsed, the depositor calls `revoke_drop` with the leaf preimage. The program verifies the preimage on-chain, creates the nullifier PDA, and refunds the deposit via direct lamport manipulation.

Constants:
- Production: `REVOKE_TIMEOUT = 2,592,000` (30 days)
- Test: `REVOKE_TIMEOUT = 5` seconds (behind the `short-revoke-timeout` Cargo feature)

### Security (Option C — preimage verification)

An earlier design (Option A) stored `nullifier_hash` in the receipt as declared by the depositor. It is BROKEN: a malicious depositor can declare a fake hash, share the claim code with a real nullifier, and double-spend — their revoke creates a PDA at the fake hash, the real claim creates a PDA at the real hash, treasury pays twice.

Option C (deployed) fixes this by requiring the depositor to submit the FULL leaf preimage `(secret, nullifier, blinding_factor)` as an opaque 96-byte field. The program:

1. Reads `amount` from the on-chain receipt (not user-supplied — can't be tampered)
2. Recomputes `leaf = Poseidon(secret, nullifier, amount, blinding_factor)` and verifies it matches `receipt.leaf`
3. Recomputes `nullifier_hash = Poseidon(nullifier)` and uses it to derive the nullifier PDA

Because `leaf` is a collision-resistant commitment to ALL four inputs, the depositor is forced to reveal the exact preimage they used. The derived `nullifier_hash` is therefore the same one any legitimate claim would produce. Claim and revoke share the `[b"nullifier", nullifier_hash]` PDA namespace, giving mutual exclusion: whichever happens first blocks the other.

### Privacy cost of revoking

**The privacy cost begins at deposit, not at revoke.**

Creating a `DepositReceipt` at deposit time creates an indexable on-chain record linking your wallet to a specific leaf and amount. This link is observable from the moment of deposit, regardless of whether the drop is later revoked or the receipt is closed. The V2 credit-note model still hides which leaf was claimed (the `leaf ↔ nullifier_hash` mapping remains private), so the receipt does NOT leak the recipient of a normal claim — but it does permanently reveal that your wallet deposited amount A with leaf L. The `close_receipt` instruction returns the rent but does not erase this from indexer history.

If you go on to exercise revoke, additional linkage is revealed on top of this:

1. Signing the revoke TX from your own wallet (same wallet already in the receipt).
2. Revealing the full leaf preimage (secret, nullifier, blinding) on-chain, which publishes the nullifier_hash for your drop.

Any observer can then correlate:
- The depositor wallet (revoke signer) with the original `create_drop` TX (same leaf).
- The revealed nullifier with the leaf (now on-chain as a nullifier PDA).
- The deposit amount (was already visible from both `create_drop` and the receipt).

Revoke's additional cost is the publication of the nullifier_hash and leaf preimage. It does NOT affect the anonymity of OTHER drops in the Merkle tree.

**What revoke does NOT break.** The claim-side anonymity of *other* users is unchanged. The revoke PDA and nullifier sharing with claim means an observer sees ONE of two events per nullifier (claim OR revoke) but never both — they cannot distinguish whether a nullifier was claimed anonymously or revoked (unless they separately correlate the revoker's wallet signature).

**Guidance for users.** The receipt path trades claim-privacy for recoverability:

- If you prioritize claim privacy: use the legacy 5-account `create_drop` call (no receipt, no revoke). Ensure your claim code is delivered reliably. This path preserves full V2 anonymity — your wallet does not appear on-chain in the deposit unless you deposit directly (not via relayer).
- If you prioritize recoverability: use the 7-account `create_drop` call. Accept that your wallet is publicly linked to the specific leaf and amount from the moment of deposit. This is true even if the drop is claimed normally and you later call `close_receipt` to reclaim the rent. The linkage does NOT compose with the claim's recipient, but it does reveal that you made the deposit.

### Closing an unused receipt

If a receipt-bearing drop is claimed normally (not revoked), the receipt PDA becomes orphaned because `revoke_drop`'s flow is blocked by the now-existing nullifier PDA. To reclaim the ~0.00151 SOL receipt rent in this case, the depositor calls `close_receipt`:

```
Instruction: close_receipt
Args:     leaf ([u8; 32])
Accounts: deposit_receipt (mut, close = depositor), depositor (signer, mut)
```

The close is unconditional: the program does not verify that the drop was claimed. The depositor is trusted to decide off-chain when closure is safe. Closing prematurely surrenders the revoke option but is otherwise harmless — only the depositor can sign.

Design rationale for unconditional close: any on-chain verification (via preimage or nullifier_hash argument) would either leak the preimage publicly (same cost as revoke) or introduce a new deposit↔close linkage source. The unconditional close was selected after explicitly rejecting re-seeding the receipt by `nullifier_hash` (would enable a trivial deposit↔claim linkage) and rejecting an auto-close inside `claim_credit` (would require the claim's account list to reference a leaf-dependent PDA, breaking V2). See Audit #4 M-01 for the full analysis.

### Backward compatibility

`create_drop` was extended via Anchor's `remaining_accounts` pattern, NOT by changing the declared account list. The five-account legacy path (vault, merkle_tree, treasury, sender, system_program) still works unchanged — the seeder and any unupdated client continue operating, they just don't get a receipt and thus no revoke capability for drops made that way.

New clients pass two additional accounts after system_program:
- `depositor` (signer, mut) — pays receipt rent, authorized to revoke
- `deposit_receipt` (mut) — PDA `[b"receipt", leaf]`

### On-chain footprint

| Step | Inner instructions | Amount visible? |
|------|-------------------|-----------------|
| create_drop with receipt | CPI Transfer (sender→treasury) + CreateAccount (receipt PDA) | Yes (deposit amount, same as before) |
| revoke_drop | 1 CreateAccount (nullifier PDA). Refund is direct lamport manipulation. | Balance delta only (no decoded Transfer) |

Same visibility profile as `withdraw_credit` — zero CPI Transfer instructions on the payout.

### DepositReceipt struct

```rust
pub struct DepositReceipt {
    pub bump: u8,
    pub depositor: Pubkey,
    pub amount: u64,
    pub created_at: i64,
    pub leaf: [u8; 32],
}
// PDA seeds: [b"receipt", leaf]
// Size: 89 bytes, rent ~0.00151 SOL (returned on revoke)
```

### New error codes

| Code | Name | Description |
|------|------|-------------|
| 6014 | RevokeTooEarly | `now < receipt.created_at + REVOKE_TIMEOUT` |
| 6015 | UnauthorizedRevoke | Signer does not match `receipt.depositor` |
| 6016 | DropAlreadyClaimed | Reserved for explicit claim/revoke race detection |
| 6017 | InvalidDepositReceipt | `create_drop` remaining_accounts failed signer/writable/PDA checks |
| 6018 | LeafAlreadyDeposited | A receipt already exists for this leaf |

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

Schema v2 (deployed 2026-04-23): **256 recent roots** stored (bumped from 30 to extend the window during which a claim-code snapshot remains verifiable on-chain). Same circular-buffer semantics — after 256 new drops, the oldest root expires.

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
| `create_drop_to_pool` | vault, note_pool, note_pool_tree, treasury, sender, system_program | amount (u64), pool_params (96 bytes) | One-TX equivalent of `create_drop` → `claim_credit` → `deposit_to_note_pool`. Sender CPI-transfers SOL; program constructs pool leaf on-chain with the verified amount. No CreditNote intermediate. |

#### Revoke trade-off for pool deposits (Audit #5 L-03)

**Pool deposits cannot be revoked.** There is no `revoke_pool_drop` instruction, and `create_drop_to_pool` does not accept a `DepositReceipt`. If the depositor loses the 96-byte `pool_params` (pool_secret + pool_nullifier + pool_blinding) before the recipient claims, the SOL is permanently locked in the treasury — counted toward `total_deposited`, protected from `admin_sweep`, but unreachable.

This is a deliberate design trade-off:

- A hypothetical `PoolDepositReceipt` keyed by `pool_leaf` would work cryptographically (the depositor could prove preimage knowledge after a time-lock), but it would permanently link depositor ↔ pool_leaf ↔ amount on-chain — the same deposit-side privacy cost documented for base-layer `DepositReceipt` under "Privacy cost of revoking" above.
- The base-layer `create_drop` path still supports opt-in `DepositReceipt` for revokability, so depositors who want the fallback should use DIRECT or PRIVATE deposit, not MAX PRIVACY.
- Audit #4 I-01 accepted this as the expected behaviour of the note pool layer; Audit #5 L-03 re-affirmed the trade-off after `create_drop_to_pool` collapsed the flow into a single TX (removing the intermediate state in which a user could previously have abandoned the deposit before it landed in the pool).

**Guidance for pool-mode depositors:** save the claim code immediately and verify it decodes cleanly before closing the deposit tab. The frontend's `/drop/create` page surfaces this warning when MAX PRIVACY is selected.

### 14. Revoke instruction for unclaimed drops

`revoke_drop` added April 20, 2026 so depositors can reclaim SOL from drops whose claim codes were lost. A `DepositReceipt` PDA is optionally created at deposit time (via `remaining_accounts` for backward compatibility with the legacy 5-account `create_drop` call). After a 30-day time-lock, the depositor submits the full leaf preimage and the program verifies `leaf == Poseidon(secret, nullifier, receipt.amount, blinding)` on-chain. Because the leaf is a collision-resistant commitment, the depositor is forced to reveal the same `nullifier` that any legitimate claimer would use — claim and revoke share the `[b"nullifier", nullifier_hash]` PDA namespace, giving mutual exclusion. Refund is via direct lamport manipulation (no CPI). See the REVOKE INSTRUCTION section above for the full design and the Option-A-was-broken rationale.

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

### migrate_vault (migration)

```
Args: none
Accounts: vault, authority, system_program
```

One-time migration: reallocates the Vault account to include the `total_deposited` and `total_withdrawn` fields used by obligation-aware accounting (`admin_sweep`, `revoke_drop`). Idempotent — returns `AlreadyMigrated` (6013) on repeat calls. Only callable by vault authority. See `scripts/migrate-vault-v2.js` for the upgrade runbook.

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
          payer, system_program
```

Uses V1 verification key (6 public inputs). Transfers SOL via direct lamport manipulation from treasury. Fee credits to `payer` directly (Audit 04 I-04: the redundant `fee_recipient` account was removed; previously constrained equal to payer). Kept for backward compatibility.

### claim_credit (V2 circuit — hidden amount)

```
Discriminator: [190, 242, 172, 79, 29, 82, 22, 163]
Args: nullifier_hash ([u8;32]), proof (ProofData), inputs (Vec<u8> — 96 bytes opaque), salt ([u8;32])
Accounts: vault, merkle_tree, credit_note, nullifier_account, recipient, payer, system_program
```

Verifies Groth16 proof using V2 circuit (5 public inputs, amount is PRIVATE). Creates CreditNote PDA storing a re-randomized Poseidon commitment: `stored_commitment = Poseidon(amount_commitment, salt)`. Marks nullifier spent. **ZERO SOL moves.** No amount anywhere in instruction data or events.

The `inputs` field is an opaque 96-byte blob: `merkle_root(32) + amount_commitment(32) + password_hash(32)`. The `salt` is caller-supplied entropy that breaks the deposit→claim commitment linkage (fixes Audit 02 M-01-NEW).

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
Args: nullifier_hash ([u8;32]), opening (Vec<u8> — 72 bytes opaque), rate (u16)
Accounts: vault, treasury, credit_note, recipient, payer, system_program
```

Opens the Poseidon commitment. Program recomputes `Poseidon(Poseidon(amount, blinding_factor), salt)` on-chain and verifies against stored commitment. Transfers SOL via direct lamport manipulation — no CPI, no inner instruction. Fee = `amount * rate / 10000`, credited to `payer` (I-04: redundant `fee_recipient` account removed). CreditNote PDA closed after withdrawal.

The `opening` field is an opaque 72-byte blob: `amount(8 LE) + blinding_factor(32) + salt(32)`.

| Index | Account | Writable | Signer |
|-------|---------|----------|--------|
| 0 | vault | yes | no |
| 1 | treasury | yes | no |
| 2 | credit_note | yes | no |
| 3 | recipient | yes | no |
| 4 | payer | yes | yes |
| 5 | system_program | no | no |

### revoke_drop

```
Args: leaf ([u8;32]), nullifier_hash ([u8;32]), preimage (Vec<u8> — 96 bytes opaque)
Accounts: vault, treasury, deposit_receipt, nullifier_account, depositor, system_program
```

Reclaim SOL from an unclaimed drop after `REVOKE_TIMEOUT` seconds. The `preimage` field is an opaque 96-byte blob: `secret(32) + nullifier(32) + blinding_factor(32)`.

On-chain: reads `amount` from the receipt (not user-supplied), recomputes `leaf = Poseidon(secret, nullifier, amount, blinding)` and `nullifier_hash = Poseidon(nullifier)`, verifies both match, creates the nullifier PDA (shared namespace with `claim_credit` — collision = already claimed), refunds via direct lamport manipulation. Receipt PDA is closed, rent returned to depositor.

Obligation-aware bound: `refund <= vault.total_deposited - vault.total_withdrawn` AND `refund <= treasury_lamports - rent_exempt_min`. Increments `total_withdrawn` on success (keeps `admin_sweep` accounting correct).

| Index | Account | Writable | Signer |
|-------|---------|----------|--------|
| 0 | vault | yes | no |
| 1 | treasury | yes | no |
| 2 | deposit_receipt | yes | no |
| 3 | nullifier_account | yes | no |
| 4 | depositor | yes | yes |
| 5 | system_program | no | no |

### close_receipt

```
Args: leaf ([u8;32])
Accounts: deposit_receipt, depositor, system_program
```

Close an orphaned DepositReceipt after a drop has been claimed normally (not revoked). Unconditional close signed by the depositor; returns ~0.00151 SOL rent. Does NOT verify that the drop was claimed — the depositor judges off-chain. Closing prematurely surrenders the revoke option. See the "Privacy cost of revoking" section for why the close is unconditional.

| Index | Account | Writable | Signer |
|-------|---------|----------|--------|
| 0 | deposit_receipt | yes | no |
| 1 | depositor | yes | yes |

### migrate_schema_v2 (migration)

```
Discriminator: [169, 82, 231, 138, 226, 218, 110, 237]
Args: none
Accounts: vault, merkle_tree, note_pool_tree, authority, system_program
```

One-time schema v2 migration: reallocates `MerkleTreeAccount` and `NotePoolTree` from 1680 bytes (ROOT_HISTORY_SIZE=30) to 8912 bytes (ROOT_HISTORY_SIZE=256). Existing roots + `filled_subtrees` are preserved; the 226 newly-allocated `root_history` slots are seeded with `ZERO_HASHES[MERKLE_DEPTH]` (also closes Audit 04 L-01 + Audit 03 L-03-NEW for pre-existing accounts). Atomic across both trees (either both migrate in one TX or neither does). Idempotent per-tree — returns `Ok` silently if already at the new size; `InvalidAccountSize` (6019) on unexpected sizes. Rent diff is paid by the authority. See `scripts/migrate-schema-v2.js` for the runbook.

### propose_authority_rotation (L-03)

```
Discriminator: [185, 202, 177, 179, 135, 170, 62, 115]
Args: new_authority (Pubkey)
Accounts: vault, pending_authority, authority, system_program
```

Current authority proposes a new authority. Creates a `PendingAuthority` sidecar PDA at `[b"pending_authority", vault.key()]`. Single-proposal-in-flight invariant: `init` fails with `AccountAlreadyInitialized` if another proposal exists — the current authority must `revoke_authority_rotation` first to re-propose. Does NOT change `vault.authority`.

### revoke_authority_rotation (L-03)

```
Discriminator: [20, 250, 65, 1, 7, 141, 159, 100]
Args: none
Accounts: vault, pending_authority (close = authority), authority
```

Current authority withdraws its own pending proposal. Closes the sidecar, rent returned to authority. Used when the proposed pubkey was wrong, or to supersede with a new proposal.

### accept_authority_rotation (L-03)

```
Discriminator: [197, 155, 6, 45, 79, 0, 106, 66]
Args: none
Accounts: vault, pending_authority (close = new_authority), new_authority
```

The proposed new authority signs to accept. Handler verifies `pending_authority.new_authority == signer` (`PendingAuthorityMismatch` 6020 otherwise — Anchor's `close =` only routes lamports, it does not check identity). Flips `vault.authority` to the signer, closes the sidecar.

### create_drop_to_pool (one-TX pool deposit)

```
Discriminator: [92, 206, 41, 22, 178, 116, 89, 63]
Args: amount (u64), pool_params (Vec<u8> — 96 bytes opaque)
Accounts: vault, note_pool, note_pool_tree, treasury, sender, system_program
```

Atomic equivalent of `create_drop` + `claim_credit` + `deposit_to_note_pool` in one TX. Eliminates the 3-TX temporal correlation an observer could exploit through the compose-three-existing-instructions path. SOL → treasury via CPI. Pool leaf = `Poseidon(pool_secret, pool_nullifier, VERIFIED_amount, pool_blinding)` — constructed on-chain from the literal CPI transfer amount, so there is no commitment-scheme opening that could lie about the amount (eliminates I-01 at the pool entry layer, same property as `deposit_to_note_pool`).

The `pool_params` field is an opaque 96-byte blob: `pool_secret(32) + pool_nullifier(32) + pool_blinding(32)`.

| Index | Account | Writable | Signer |
|-------|---------|----------|--------|
| 0 | vault | yes | no |
| 1 | note_pool | yes | no |
| 2 | note_pool_tree | yes | no |
| 3 | treasury | yes | no |
| 4 | sender | yes | yes |
| 5 | system_program | no | no |

Claim codes for drops created via this instruction carry `"f": "pool"` in the claim-code payload — the frontend dispatches to the V3 proof + `claim_from_note_pool` path automatically. See [CLAIM CODE FORMAT](#claim-code-format) below.

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
    pub commitment: [u8; 32],      // Poseidon(Poseidon(amount, blinding_factor), salt) — re-randomized
    pub nullifier_hash: [u8; 32],
    pub salt: [u8; 32],
    pub created_at: i64,
}
// PDA seeds: [b"credit", nullifier_hash]
// Size: 145 bytes, rent ~0.00191 SOL (returned on close)
```

### PendingAuthority struct (L-03 sidecar)

```rust
pub struct PendingAuthority {
    pub bump: u8,
    pub vault: Pubkey,
    pub proposer: Pubkey,        // current authority at propose time
    pub new_authority: Pubkey,   // the proposed new authority
    pub proposed_at: i64,
}
// PDA seeds: [b"pending_authority", vault.key()]
// Size: 113 bytes. One pending proposal per vault at a time.
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
| 6012 | BelowMinDeposit | Deposit amount below configured minimum |
| 6013 | AlreadyMigrated | `migrate_vault` called on a vault already migrated |
| 6014 | RevokeTooEarly | `now < receipt.created_at + REVOKE_TIMEOUT` |
| 6015 | UnauthorizedRevoke | Signer does not match `receipt.depositor` |
| 6016 | DropAlreadyClaimed | Reserved for explicit claim/revoke race detection |
| 6017 | InvalidDepositReceipt | `create_drop` remaining_accounts failed signer/writable/PDA checks |
| 6018 | LeafAlreadyDeposited | A receipt already exists for this leaf |
| 6019 | InvalidAccountSize | `migrate_schema_v2`: tree account size does not match any known schema version |
| 6020 | PendingAuthorityMismatch | `accept_authority_rotation`: signer does not match the proposed new authority |

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

### Revoke & close_receipt Tests (localnet)

| Script | Coverage | Status |
|--------|----------|--------|
| `scripts/revoke-test.js` | E2E: create drop with receipt → wait time-lock → revoke → verify refund, receipt closed, nullifier created, no Transfer inner instructions | PASS |
| `scripts/security-revoke-tests.js` | 11 attack vectors: 6 revoke (before-timeout, non-depositor, after-claim, double-revoke, wrong-leaf, cross-receipt preimage) + 5 close_receipt (non-depositor, nonexistent, wrong-leaf, revoke-after-close, double-close) | 11/11 PASS |
| `scripts/revoke-crossimpl-test.js` | BE endianness consistency across frontend `amountToFieldBE`, circuit `amount` field element, and program `u64_to_field_be` | PASS |
| `scripts/legacy-create-drop-test.js` | Backward compat: 5-account `create_drop` succeeds, produces no receipt, subsequent `claim_credit` works | PASS |
| `scripts/close-receipt-test.js` | E2E: create drop with receipt → claim normally (not revoke) → close_receipt → verify receipt closed, depositor refunded, nullifier PDA + CreditNote untouched | PASS |

Run localnet tests with the `short-revoke-timeout` Cargo feature so the 30-day wait becomes 5 seconds:

```
cd program && cargo build-sbf --features short-revoke-timeout
cp target/sbpf-solana-solana/release/darkdrop.so target/deploy/darkdrop.so
# solana-test-validator --reset; solana program deploy ...
PROGRAM_ID=<deployed> node scripts/revoke-test.js
PROGRAM_ID=<deployed> node scripts/security-revoke-tests.js
```

---

## AUDITS

Four audit reports have been published, all in [`/audits/`](audits/). The [audit README](audits/README.md) contains the summary table and the fix tracker.

| # | Report | Date | Scope | Headline findings |
|---|--------|------|-------|-------------------|
| 1 | [Manual Review](audits/AUDIT-01-MANUAL-REVIEW.md) | 2026-04-06 | Fee system, credit notes, treasury, relay trust | 1 HIGH (fixed), 2 MEDIUM (accepted), 1 LOW |
| 2 | [Code Review](audits/AUDIT-02-CODE-REVIEW.md) | 2026-04-07 | Full instruction-level review | 2 HIGH, 4 MEDIUM, 4 LOW, 7 INFO |
| 3 | [Post-Fix Review](audits/AUDIT-03-POST-FIX-REVIEW.md) | 2026-04-08 | Fix verification + `admin_sweep` + re-audit | 1 HIGH, 3 MEDIUM, 3 LOW, 4 INFO (HIGH + 3 MEDIUMs fixed in-cycle) |
| 4 | [Post-Revoke Review](audits/AUDIT-04-POST-REVOKE.md) | 2026-04-20 | V3 Note Pool + `revoke_drop` + `DepositReceipt` + counter invariants + privacy | 0 CRITICAL, 0 HIGH, 1 MEDIUM (fixed in-cycle), 4 LOW, 4 INFO |

Scope-wide posture: no open HIGH or CRITICAL findings as of Audit 04. Open LOWs tracked in [`audits/README.md`](audits/README.md) are drop_cap validation, authority rotation, and zero-initialized root history (main + note_pool trees).

DarkDrop has **not** yet commissioned a third-party firm review. Deployment is restricted to Solana devnet until that step is completed.

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
  "v": "base58_vault_address",
  "p": "base64url_path_snapshot",
  "f": "pool"
}
```

`p` (optional): base64url-encoded 672-byte tree snapshot (root(32) + filled_subtrees(20×32)). Captured at deposit time so the claim path doesn't scan event logs — lets the recipient reconstruct the Merkle proof against the insertion-time root. Codes without `p` fall back to event-log replay (slow, fragile on public RPC).

`f` (optional): flavor tag. Absent or `"standard"` = base-layer flow (claim_credit → withdraw_credit, V2 proof, main merkle_tree). `"pool"` = note-pool flow (claim_from_note_pool → withdraw_credit, V3 proof, note_pool_tree). For pool codes, the `s` / `n` / `b` slots carry `pool_secret` / `pool_nullifier` / `pool_blinding` — same JSON encoding, different semantic. The claim page dispatches on this field.

### Encryption

- `raw`: base64url-encoded JSON, anyone with code can claim
- `aes:{hint}:{payload}`: AES-256-GCM encrypted, password required (legacy decode-only)
- `pbkdf2:{hint}:{payload}`: PBKDF2-derived AES-256-GCM, password required

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
| `POST /api/relay/create-drop-to-pool` | MAX PRIVACY deposit — user sends SOL to relayer, relayer calls create_drop_to_pool |
| `POST /api/relay/pool/claim` | Gasless V3 pool claim — relayer submits claim_from_note_pool with recipient-built proof |

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
| /drop/create | Wired to devnet | Three deposit modes: DIRECT, PRIVATE DEPOSIT (via relayer), MAX PRIVACY (pool, via relayer). Optional revoke toggle on DIRECT mode (creates DepositReceipt). |
| /drop/claim | Wired to devnet | Two-TX flow: claim_credit (or claim_from_note_pool for pool-flavored codes) + withdraw_credit. Gasless/direct toggle. V2 and V3 proofs generated in-browser via snarkjs WASM. |
| /drop/manage | Wired to devnet | Lists stored receipts per-wallet with on-chain status (LOCKED / REVOKABLE / CLAIMED·ORPHAN / RESOLVED). Revoke, close_receipt, and snapshot-staleness actions. |

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
- `note_pool.wasm` (2.5 MB) — V3 prover
- `note_pool_final.zkey` (5.8 MB) — V3 proving key (loaded when claim page detects a pool-flavored code)

### Instruction discriminators (hardcoded in frontend)

```
create_drop:          [157, 142, 145, 247,  92,  73,  59,  48]
claim_credit:         [190, 242, 172,  79,  29,  82,  22, 163]
withdraw_credit:      [  8, 173, 134, 129,  40, 255, 134,  30]
create_drop_to_pool:  [ 92, 206,  41,  22, 178, 116,  89,  63]
claim_from_note_pool: [253,   6, 222,  21, 191, 226,  43, 142]
revoke_drop:          [191, 194,  86,  39, 243, 136,  64,  16]
close_receipt:        [126, 254, 244, 203, 124, 164, 134,  89]
```

---

## FILE LOCATIONS

### Program

| File | Purpose |
|------|---------|
| `program/programs/darkdrop/src/lib.rs` | Entry point, 18 instruction routing |
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
| `program/programs/darkdrop/src/errors.rs` | DarkDropError enum (21 variants, codes 6000–6020) |
| `program/programs/darkdrop/src/verifier.rs` | verify_proof (V1) + verify_proof_v2 (V2) + verify_proof_v3 (V3) |
| `program/programs/darkdrop/src/vk.rs` | Triple VK: verifying_key_v1() + verifying_key_v2() + verifying_key_v3() |
| `program/programs/darkdrop/src/poseidon.rs` | On-chain Poseidon hash (light-hasher, 2-input + 4-input) |
| `program/programs/darkdrop/src/merkle_tree.rs` | Merkle tree append (main tree + note pool tree) |
| `program/idl/darkdrop.json` | Hand-written IDL v0.3.0 (obfuscated names, STALE — see KNOWN ISSUES) |
| `program/programs/darkdrop/src/instructions/migrate_vault.rs` | migrate_vault (one-time vault realloc for obligation fields) |
| `program/programs/darkdrop/src/instructions/revoke_drop.rs` | revoke_drop (30-day time-locked refund, preimage-verified) |
| `program/programs/darkdrop/src/instructions/close_receipt.rs` | close_receipt (unconditional rent recovery for orphaned receipts) |
| `program/programs/darkdrop/src/instructions/migrate_schema_v2.rs` | migrate_schema_v2 (one-time realloc of both trees to ROOT_HISTORY_SIZE=256) |
| `program/programs/darkdrop/src/instructions/authority_rotation.rs` | propose/revoke/accept_authority_rotation (L-03 sidecar) |
| `program/programs/darkdrop/src/instructions/create_drop_to_pool.rs` | create_drop_to_pool (one-TX direct pool entry) |
| `program/target/deploy/darkdrop.so` | Compiled program binary (667 KB) |

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
| `scripts/revoke-test.js` | Revoke E2E (deposit → wait → revoke → refund) |
| `scripts/security-revoke-tests.js` | 11 revoke + close_receipt security tests |
| `scripts/close-receipt-test.js` | close_receipt E2E (claim normally → close receipt → refund rent) |
| `scripts/revoke-crossimpl-test.js` | BE endianness parity across frontend, circuit, program |
| `scripts/legacy-create-drop-test.js` | Backward-compat check for 5-account create_drop |
| `scripts/stress-test.js` | Multi-wallet stress test (10 deposits, 10 claims, 5 wallets/side) |
| `scripts/migrate-vault-v2.js` | Runbook: invoke migrate_vault on existing deployment |
| `scripts/dump-account-sizes.js` | Pre-flight: snapshot current tree + vault sizes to migration-baseline.json |
| `scripts/migrate-schema-v2.js` | Runbook: invoke migrate_schema_v2 (idempotent, asserts baseline) |
| `scripts/e2e-pool-deposit-test.js` | E2E: create_drop_to_pool → claim_from_note_pool → withdraw_credit |
| `scripts/test_poseidon_compat.js` | Poseidon parity check (JS ↔ Rust light-hasher) |
| `scripts/generate_zero_hashes.js` | Precompute empty-tree zero hashes for Merkle init |
| `scripts/generate-audit-pdfs.js` | Render `/audits/*.md` to PDF |
| `scripts/export_vk_rust.js` | Convert verification_key.json to Rust constants |

### Relayer

| File | Purpose |
|------|---------|
| `relayer/src/index.ts` | Express server, routes, health check |
| `relayer/src/config.ts` | Configuration |
| `relayer/src/routes/claim.ts` | Legacy claim relay |
| `relayer/src/routes/deposit.ts` | Deposit relay (private deposit) |
| `relayer/src/routes/credit.ts` | Credit claim + withdraw relay |
| `relayer/src/routes/pool.ts` | MAX PRIVACY deposit relay (create_drop_to_pool) |
| `relayer/src/routes/pool-claim.ts` | Gasless V3 pool claim relay (claim_from_note_pool) |

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

2. **Anonymity set is small.** Vault has ~230+ leaves on devnet. Seeder running 24/7 on Jetson adds 15–30 drops/day with diverse amounts.

3. **No SPL token support.** Only SOL.

4. **`anchor build` broken.** Must use `cargo build-sbf`. IDL hand-written.

5. **No QR codes, burn links, or history page.** Core flow only.

6. **Deposit amount still visible.** The `create_drop` CPI transfer reveals the deposit amount. This is fundamental — SOL must physically move. The credit note model hides the amount at claim time and decorrelates it at withdraw time, but the deposit itself is public. `create_drop_to_pool` has the same deposit-time visibility.

7. **Relayer deployed on Jetson behind a Cloudflare tunnel.** Production-ready for the current scale. Migration to a public VPS is not blocking.

8. **~~Frontend does not yet surface revoke.~~** RESOLVED (2026-04-23). `/drop/create` exposes the revoke toggle (7-account `create_drop` with `DepositReceipt` creation). `/drop/manage` lists a user's stored receipts with revoke + close_receipt actions and a snapshot-staleness badge.

9. **IDL is stale vs deployed binary.** The hand-written IDL (`program/idl/darkdrop.json`, v0.3.0) declares 13 instructions; the deployed program exposes 18. Still missing from IDL: `create_treasury`, `admin_sweep`, `migrate_vault`, `revoke_drop`, `close_receipt` (all pre-existing gaps; schema v2 and note-pool sessions added their new instructions to the IDL). Block explorers and Anchor-based SDK clients cannot decode calls to those 5 instructions — the frontend hardcodes discriminators instead. Fix: add the 5 remaining instructions to the hand-written IDL and run `anchor idl upgrade` against the deployed program.

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
- **One-TX pool entry** via `create_drop_to_pool` — eliminates the 3-TX temporal correlation of compose-three-ixs pool deposits
- **Dishonest leaf elimination** at pool layer (program constructs pool leaves with verified amounts — same property whether entering via `deposit_to_note_pool` or `create_drop_to_pool`)
- Depositor fallback via **30-day revoke path** for unclaimed drops (sender-keyed, preimage-verified, shares nullifier namespace with claim so double-spend is impossible)
- **Extended root history** (256 slots, schema v2) — claim-code snapshots remain verifiable on-chain for ~1–2 weeks of devnet activity before rotating out
- **Authority rotation** via propose/accept sidecar PDA — no Vault realloc, single-proposal invariant, new authority must sign acceptance

---

*End of current state document.*
