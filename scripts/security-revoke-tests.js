#!/usr/bin/env node
/**
 * DarkDrop V4 — Revoke Security Tests
 *
 * Attack vectors:
 *   A) Revoke before timeout           → RevokeTooEarly
 *   B) Non-depositor tries to revoke   → UnauthorizedRevoke
 *   C) Revoke after the drop is claimed → init nullifier PDA fails
 *   D) Double-revoke                   → init nullifier PDA fails on 2nd attempt
 *   E) Revoke with wrong leaf arg      → receipt PDA derivation fails
 *   F) Revoke drop A with drop B's preimage → CommitmentMismatch
 *      (receipt PDA is looked up by leaf, so the amount used for leaf
 *      reconstruction is drop A's amount; drop B's preimage doesn't match.)
 *
 * Run against localnet:
 *   solana-test-validator --reset
 *   cargo build-sbf --features short-revoke-timeout
 *   cp program/target/sbpf-solana-solana/release/darkdrop.so program/target/deploy/
 *   solana program deploy program/target/deploy/darkdrop.so
 *   node scripts/security-revoke-tests.js
 */

const {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  ComputeBudgetProgram,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} = require("@solana/web3.js");
const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey(process.env.PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");
const BUILD_DIR = path.join(__dirname, "../circuits/build");
const WASM_PATH = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const ZKEY_PATH = path.join(BUILD_DIR, "darkdrop_v2_final.zkey");
const DROP_CAP = BigInt(100 * LAMPORTS_PER_SOL);
const TIMEOUT_WAIT_MS = parseInt(process.env.REVOKE_WAIT_MS || "8000", 10);
const MERKLE_DEPTH = 20;
const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

let poseidon, F;

function poseidonHash(inputs) { return F.toObject(poseidon(inputs)); }
function randomField() { return BigInt("0x" + crypto.randomBytes(31).toString("hex")); }

function bytesToBigIntBE(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return BigInt("0x" + (hex || "0"));
}

function bigintToBytes32BE(val) {
  const hex = val.toString(16).padStart(64, "0");
  const bytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function bigintToBE32(val) {
  const hex = BigInt(val).toString(16).padStart(64, "0");
  const buf = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) buf[i] = parseInt(hex.substr(i * 2, 2), 16);
  return buf;
}

function pubkeyToField(pubkeyBytes) {
  const hi = bytesToBigIntBE(pubkeyBytes.slice(0, 16));
  const lo = bytesToBigIntBE(pubkeyBytes.slice(16, 32));
  return poseidonHash([hi, lo]);
}

function getDiscriminator(name) {
  return crypto.createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function getVaultPDA() { return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID); }
function getMerkleTreePDA(vault) { return PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID); }
function getTreasuryPDA() { return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID); }
function getNullifierPDA(nullifierHash) { return PublicKey.findProgramAddressSync([Buffer.from("nullifier"), nullifierHash], PROGRAM_ID); }
function getCreditNotePDA(nullifierHash) { return PublicKey.findProgramAddressSync([Buffer.from("credit"), nullifierHash], PROGRAM_ID); }
function getReceiptPDA(leafBytes) { return PublicKey.findProgramAddressSync([Buffer.from("receipt"), leafBytes], PROGRAM_ID); }

function getZeroHashes() {
  const zeros = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) zeros.push(poseidonHash([zeros[i], zeros[i]]));
  return zeros;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

let connection, payer;
let vault, merkleTree, treasury;

async function ensureVault() {
  const initDiscriminator = getDiscriminator("initialize_vault");
  const dropCapBuf = Buffer.alloc(8);
  dropCapBuf.writeBigUInt64LE(DROP_CAP);

  const initIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([initDiscriminator, dropCapBuf]),
  });
  try {
    await sendAndConfirmTransaction(connection, new Transaction().add(initIx), [payer]);
  } catch (e) {
    if (!e.message?.includes("already in use")) throw e;
  }
}

/**
 * Create a drop with DepositReceipt. Returns { secret, nullifier, blinding,
 * amount, leafBytes, nullifierHashBytes, receipt, depositor }.
 */
async function createDropWithReceipt(depositor, amount) {
  const secret = randomField();
  const nullifier = randomField();
  const blinding = randomField();
  const leafBig = poseidonHash([secret, nullifier, amount, blinding]);
  const leafBytes = bigintToBytes32BE(leafBig);
  const amtCommitment = poseidonHash([amount, blinding]);
  const [receipt] = getReceiptPDA(leafBytes);
  const nullifierHashBig = poseidonHash([nullifier]);
  const nullifierHashBytes = bigintToBytes32BE(nullifierHashBig);

  const amountBuf = Buffer.alloc(8);
  amountBuf.writeBigUInt64LE(amount);

  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: depositor.publicKey, isSigner: true, isWritable: true },
      { pubkey: receipt, isSigner: false, isWritable: true },
    ],
    data: Buffer.concat([
      getDiscriminator("create_drop"),
      leafBytes,
      amountBuf,
      bigintToBytes32BE(amtCommitment),
      bigintToBytes32BE(0n),
    ]),
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(ix), [payer, depositor]);

  return {
    secret, nullifier, blinding, amount,
    leafBytes, nullifierHashBytes,
    receipt, depositor,
    amtCommitment,
  };
}

function buildCloseReceiptIx({ leafBytes, receipt, depositorKey }) {
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: receipt, isSigner: false, isWritable: true },
      { pubkey: depositorKey, isSigner: true, isWritable: true },
    ],
    data: Buffer.concat([
      getDiscriminator("close_receipt"),
      leafBytes,
    ]),
  });
}

function buildRevokeIx({ leafBytes, nullifierHashBytes, secret, nullifier, blinding, receipt, depositorKey }) {
  const [nullifierPDA] = getNullifierPDA(nullifierHashBytes);
  const preimage = Buffer.concat([
    bigintToBytes32BE(secret),
    bigintToBytes32BE(nullifier),
    bigintToBytes32BE(blinding),
  ]);
  const preimageLenBuf = Buffer.alloc(4);
  preimageLenBuf.writeUInt32LE(preimage.length);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: receipt, isSigner: false, isWritable: true },
      { pubkey: nullifierPDA, isSigner: false, isWritable: true },
      { pubkey: depositorKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      getDiscriminator("revoke_drop"),
      leafBytes,
      nullifierHashBytes,
      preimageLenBuf, preimage,
    ]),
  });
}

async function expectFail(label, buildTx, expectedPattern) {
  try {
    const sig = await sendAndConfirmTransaction(connection, buildTx(), buildTx.signers);
    console.log(`  [FAIL] ${label}: TX unexpectedly succeeded (${sig})`);
    return false;
  } catch (e) {
    const msg = e.message + (e.logs ? "\n" + e.logs.join("\n") : "");
    const matches = expectedPattern ? expectedPattern.test(msg) : true;
    if (matches) {
      console.log(`  [PASS] ${label}: TX failed as expected`);
      return true;
    }
    console.log(`  [FAIL] ${label}: TX failed but with wrong error`);
    console.log(`         Expected: ${expectedPattern}`);
    console.log(`         Got: ${e.message}`);
    if (e.logs) e.logs.slice(-8).forEach(l => console.log(`           ${l}`));
    return false;
  }
}

/**
 * Produce a valid V2 proof + claim_credit for the given drop. Needed for test C.
 */
async function claimDropAsCreditNote(drop, recipient) {
  const treeInfo = await connection.getAccountInfo(merkleTree);
  const treeData = treeInfo.data;
  const nextIndex = treeData.readUInt32LE(8 + 32);
  const onChainRoot = treeData.slice(8 + 32 + 4 + 4, 8 + 32 + 4 + 4 + 32);
  const filledSubtreesOffset = 8 + 32 + 4 + 4 + 32 + 30 * 32;
  const filledSubtrees = [];
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    filledSubtrees.push(treeData.slice(filledSubtreesOffset + i * 32, filledSubtreesOffset + (i + 1) * 32));
  }

  // Find this drop's leaf by scanning back — we know its index is nextIndex-1
  // only if it's the most recent. For this test it IS the most recent (we just
  // created it), so use nextIndex-1.
  const leafIndex = nextIndex - 1;
  const onChainRootBigInt = bytesToBigIntBE(onChainRoot);

  const zeroHashes = getZeroHashes();
  const pathElements = [], pathIndices = [];
  let idx = leafIndex;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    const bit = idx & 1;
    pathIndices.push(bit.toString());
    pathElements.push(bit === 0 ? zeroHashes[i].toString() : bytesToBigIntBE(filledSubtrees[i]).toString());
    idx = idx >> 1;
  }

  const recipientField = pubkeyToField(recipient.publicKey.toBytes());
  const nullHashBig = bytesToBigIntBE(drop.nullifierHashBytes);

  const circuitInput = {
    secret: drop.secret.toString(),
    amount: drop.amount.toString(),
    blinding_factor: drop.blinding.toString(),
    nullifier: drop.nullifier.toString(),
    merkle_path: pathElements,
    merkle_indices: pathIndices,
    password: "0",
    merkle_root: onChainRootBigInt.toString(),
    nullifier_hash: nullHashBig.toString(),
    recipient: recipientField.toString(),
    amount_commitment: drop.amtCommitment.toString(),
    password_hash: "0",
  };

  const { proof } = await snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);

  const proofA_y_neg = BN254_FQ - BigInt(proof.pi_a[1]);
  const proofA = Buffer.concat([bigintToBE32(proof.pi_a[0]), bigintToBE32(proofA_y_neg)]);
  const proofB = Buffer.concat([
    bigintToBE32(proof.pi_b[0][1]), bigintToBE32(proof.pi_b[0][0]),
    bigintToBE32(proof.pi_b[1][1]), bigintToBE32(proof.pi_b[1][0]),
  ]);
  const proofC = Buffer.concat([bigintToBE32(proof.pi_c[0]), bigintToBE32(proof.pi_c[1])]);

  const opaqueInputs = Buffer.concat([
    onChainRoot,
    bigintToBytes32BE(drop.amtCommitment),
    bigintToBytes32BE(0n),
  ]);
  const inputsLenBuf = Buffer.alloc(4);
  inputsLenBuf.writeUInt32LE(opaqueInputs.length);

  const salt = randomField();

  const data = Buffer.concat([
    getDiscriminator("claim_credit"),
    drop.nullifierHashBytes,
    proofA, proofB, proofC,
    inputsLenBuf, opaqueInputs,
    bigintToBytes32BE(salt),
  ]);

  const [nullifierPDA] = getNullifierPDA(drop.nullifierHashBytes);
  const [creditNotePDA] = getCreditNotePDA(drop.nullifierHashBytes);

  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: false },
      { pubkey: creditNotePDA, isSigner: false, isWritable: true },
      { pubkey: nullifierPDA, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  const tx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
    ix,
  );
  await sendAndConfirmTransaction(connection, tx, [payer]);
}

async function main() {
  console.log("=== DarkDrop V4 — Revoke Security Tests ===\n");

  poseidon = await buildPoseidon();
  F = poseidon.F;

  connection = new Connection(RPC_URL, {
    commitment: "confirmed",
    confirmTransactionInitialTimeout: 120000,
  });
  payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));

  [vault] = getVaultPDA();
  [merkleTree] = getMerkleTreePDA(vault);
  [treasury] = getTreasuryPDA();

  await ensureVault();

  let pass = 0, fail = 0;
  const record = (ok) => { if (ok) pass++; else fail++; };

  // ============================================================
  // TEST A: Revoke before timeout expires → RevokeTooEarly
  // ============================================================
  console.log("\n[A] Revoke before timeout → RevokeTooEarly");
  {
    const depositor = Keypair.generate();
    await connection.confirmTransaction(
      await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)
    );
    const drop = await createDropWithReceipt(depositor, BigInt(0.02 * LAMPORTS_PER_SOL));

    const build = () => new Transaction().add(buildRevokeIx({
      ...drop,
      depositorKey: depositor.publicKey,
    }));
    build.signers = [depositor];
    record(await expectFail("A", build, /RevokeTooEarly|0x17de|6014/));
  }

  // ============================================================
  // TEST B: Non-depositor tries to revoke → UnauthorizedRevoke
  // ============================================================
  console.log("\n[B] Non-depositor signer → UnauthorizedRevoke");
  {
    const depositor = Keypair.generate();
    const attacker = Keypair.generate();
    await Promise.all([
      connection.confirmTransaction(await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)),
      connection.confirmTransaction(await connection.requestAirdrop(attacker.publicKey, 0.1 * LAMPORTS_PER_SOL)),
    ]);
    const drop = await createDropWithReceipt(depositor, BigInt(0.02 * LAMPORTS_PER_SOL));

    console.log(`    waiting ${TIMEOUT_WAIT_MS}ms for timeout...`);
    await sleep(TIMEOUT_WAIT_MS);

    const build = () => new Transaction().add(buildRevokeIx({
      ...drop,
      depositorKey: attacker.publicKey,
    }));
    build.signers = [attacker];
    record(await expectFail("B", build, /UnauthorizedRevoke|0x17df|6015/));
  }

  // ============================================================
  // TEST C: Revoke after drop is claimed → nullifier exists
  // ============================================================
  console.log("\n[C] Revoke after claim_credit → nullifier PDA collision");
  {
    const depositor = Keypair.generate();
    const recipient = Keypair.generate();
    await connection.confirmTransaction(
      await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)
    );
    const drop = await createDropWithReceipt(depositor, BigInt(0.02 * LAMPORTS_PER_SOL));

    // Claim the drop first
    await claimDropAsCreditNote(drop, recipient);

    console.log(`    waiting ${TIMEOUT_WAIT_MS}ms for timeout...`);
    await sleep(TIMEOUT_WAIT_MS);

    const build = () => new Transaction().add(buildRevokeIx({
      ...drop,
      depositorKey: depositor.publicKey,
    }));
    build.signers = [depositor];
    record(await expectFail("C", build, /already in use|0x0/));
  }

  // ============================================================
  // TEST D: Double-revoke → nullifier exists on 2nd attempt
  // ============================================================
  console.log("\n[D] Double-revoke → nullifier PDA collision on 2nd attempt");
  {
    const depositor = Keypair.generate();
    await connection.confirmTransaction(
      await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)
    );
    const drop = await createDropWithReceipt(depositor, BigInt(0.02 * LAMPORTS_PER_SOL));

    console.log(`    waiting ${TIMEOUT_WAIT_MS}ms for timeout...`);
    await sleep(TIMEOUT_WAIT_MS);

    // First revoke should succeed
    const firstTx = new Transaction().add(buildRevokeIx({
      ...drop,
      depositorKey: depositor.publicKey,
    }));
    try {
      await sendAndConfirmTransaction(connection, firstTx, [depositor]);
      console.log("    first revoke succeeded (expected)");
    } catch (e) {
      console.log("  [FAIL] D setup: first revoke should have succeeded:", e.message);
      fail++;
      // fall through — the nullifier is still stored if it got that far
    }

    // The receipt was closed by the first revoke, so the second will fail on
    // receipt PDA lookup (AccountNotInitialized) — NOT on the nullifier. Both
    // outcomes prevent double-revoke; we accept either.
    const build = () => new Transaction().add(buildRevokeIx({
      ...drop,
      depositorKey: depositor.publicKey,
    }));
    build.signers = [depositor];
    record(await expectFail("D", build, /already in use|AccountNotInitialized|3012|0x0|0xbc4/));
  }

  // ============================================================
  // TEST E: Wrong leaf arg (no matching receipt) → derivation fails
  // ============================================================
  console.log("\n[E] Wrong leaf arg → receipt PDA derivation mismatch");
  {
    const depositor = Keypair.generate();
    await connection.confirmTransaction(
      await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)
    );
    const drop = await createDropWithReceipt(depositor, BigInt(0.02 * LAMPORTS_PER_SOL));

    console.log(`    waiting ${TIMEOUT_WAIT_MS}ms for timeout...`);
    await sleep(TIMEOUT_WAIT_MS);

    // Use a random bogus leaf in args — receipt PDA derived from it does not
    // exist on-chain.
    const bogusLeafBytes = crypto.randomBytes(32);
    const [bogusReceipt] = getReceiptPDA(bogusLeafBytes);

    const build = () => new Transaction().add(buildRevokeIx({
      leafBytes: bogusLeafBytes,
      nullifierHashBytes: drop.nullifierHashBytes,
      secret: drop.secret,
      nullifier: drop.nullifier,
      blinding: drop.blinding,
      receipt: bogusReceipt,
      depositorKey: depositor.publicKey,
    }));
    build.signers = [depositor];
    record(await expectFail("E", build, /AccountNotInitialized|3012|0xbc4/));
  }

  // ============================================================
  // TEST F: Cross-receipt preimage attack
  //   Depositor creates drops A and B. Tries to revoke drop A using drop B's
  //   preimage. Receipt PDA lookup is by drop A's leaf, so the program uses
  //   drop A's amount to reconstruct the leaf — drop B's preimage will not
  //   match. Expected: CommitmentMismatch.
  // ============================================================
  console.log("\n[F] Cross-receipt preimage attack → CommitmentMismatch");
  {
    const depositor = Keypair.generate();
    await connection.confirmTransaction(
      await connection.requestAirdrop(depositor.publicKey, 0.2 * LAMPORTS_PER_SOL)
    );
    const dropA = await createDropWithReceipt(depositor, BigInt(0.02 * LAMPORTS_PER_SOL));
    const dropB = await createDropWithReceipt(depositor, BigInt(0.03 * LAMPORTS_PER_SOL));

    console.log(`    waiting ${TIMEOUT_WAIT_MS}ms for timeout...`);
    await sleep(TIMEOUT_WAIT_MS);

    // Build a revoke where the accounts/args target drop A, but the preimage
    // and nullifier_hash come from drop B. The nullifier_hash passed is still
    // valid (matches Poseidon(nullifier_B)), but the reconstructed leaf using
    // dropA.amount will not match dropA.leaf.
    const build = () => new Transaction().add(buildRevokeIx({
      leafBytes: dropA.leafBytes,                   // PDA derivation → dropA receipt
      nullifierHashBytes: dropB.nullifierHashBytes, // nullifier for dropB
      secret: dropB.secret,
      nullifier: dropB.nullifier,
      blinding: dropB.blinding,
      receipt: dropA.receipt,
      depositorKey: depositor.publicKey,
    }));
    build.signers = [depositor];
    record(await expectFail("F", build, /CommitmentMismatch|0x17d9|6009/));
  }

  // ============================================================
  // TEST G: close_receipt by non-depositor → InvalidDepositReceipt
  //   Attacker signs close_receipt with a valid leaf whose receipt exists,
  //   but attacker is not the receipt's recorded depositor.
  //   Anchor's `close = depositor` only routes lamports to the signer's
  //   wallet; it does NOT check signer == receipt.depositor. The explicit
  //   require_keys_eq! in the handler is what blocks this.
  // ============================================================
  console.log("\n[G] close_receipt by non-depositor → InvalidDepositReceipt");
  {
    const depositor = Keypair.generate();
    const attacker = Keypair.generate();
    await Promise.all([
      connection.confirmTransaction(await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)),
      connection.confirmTransaction(await connection.requestAirdrop(attacker.publicKey, 0.1 * LAMPORTS_PER_SOL)),
    ]);
    const drop = await createDropWithReceipt(depositor, BigInt(0.02 * LAMPORTS_PER_SOL));

    const build = () => new Transaction().add(buildCloseReceiptIx({
      leafBytes: drop.leafBytes,
      receipt: drop.receipt,
      depositorKey: attacker.publicKey,
    }));
    build.signers = [attacker];
    record(await expectFail("G", build, /InvalidDepositReceipt|0x17e1|6017/));
  }

  // ============================================================
  // TEST H: close_receipt on nonexistent receipt → AccountNotInitialized
  //   No receipt has ever been created for this leaf. Anchor's seeds+bump
  //   constraint tries to load the account and fails.
  // ============================================================
  console.log("\n[H] close_receipt on nonexistent receipt → AccountNotInitialized");
  {
    const depositor = Keypair.generate();
    await connection.confirmTransaction(
      await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)
    );
    // Random leaf with no receipt ever created
    const fakeLeafBytes = crypto.randomBytes(32);
    const [fakeReceipt] = getReceiptPDA(fakeLeafBytes);

    const build = () => new Transaction().add(buildCloseReceiptIx({
      leafBytes: fakeLeafBytes,
      receipt: fakeReceipt,
      depositorKey: depositor.publicKey,
    }));
    build.signers = [depositor];
    record(await expectFail("H", build, /AccountNotInitialized|3012|0xbc4/));
  }

  // ============================================================
  // TEST I: close_receipt with wrong leaf arg → seed derivation fails
  //   Pass a real receipt account, but the leaf arg doesn't match it.
  //   Anchor re-derives the expected PDA from the leaf arg and rejects.
  // ============================================================
  console.log("\n[I] close_receipt with wrong leaf arg → ConstraintSeeds");
  {
    const depositor = Keypair.generate();
    await connection.confirmTransaction(
      await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)
    );
    const drop = await createDropWithReceipt(depositor, BigInt(0.02 * LAMPORTS_PER_SOL));

    // Pass the real receipt account but a bogus leaf arg. Anchor's
    // `seeds = [b"receipt", leaf.as_ref()]` with bogus leaf derives a
    // different expected PDA, triggering ConstraintSeeds.
    const bogusLeafBytes = crypto.randomBytes(32);
    const build = () => new Transaction().add(buildCloseReceiptIx({
      leafBytes: bogusLeafBytes,
      receipt: drop.receipt,
      depositorKey: depositor.publicKey,
    }));
    build.signers = [depositor];
    record(await expectFail("I", build, /ConstraintSeeds|seeds constraint|2006|0x7d6/));
  }

  // ============================================================
  // TEST J: close_receipt followed by revoke_drop → revoke fails
  //   After close_receipt, the receipt PDA is gone. A subsequent revoke
  //   attempt fails on the receipt PDA lookup.
  // ============================================================
  console.log("\n[J] close_receipt then revoke → revoke fails");
  {
    const depositor = Keypair.generate();
    await connection.confirmTransaction(
      await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)
    );
    const drop = await createDropWithReceipt(depositor, BigInt(0.02 * LAMPORTS_PER_SOL));

    // Close the receipt first
    const closeIx = buildCloseReceiptIx({
      leafBytes: drop.leafBytes,
      receipt: drop.receipt,
      depositorKey: depositor.publicKey,
    });
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(closeIx), [depositor]);
      console.log("    close_receipt succeeded (expected)");
    } catch (e) {
      console.log("  [FAIL] J setup: close_receipt should have succeeded:", e.message);
      fail++;
    }

    console.log(`    waiting ${TIMEOUT_WAIT_MS}ms for timeout...`);
    await sleep(TIMEOUT_WAIT_MS);

    // Now try to revoke — receipt is gone
    const build = () => new Transaction().add(buildRevokeIx({
      ...drop,
      depositorKey: depositor.publicKey,
    }));
    build.signers = [depositor];
    record(await expectFail("J", build, /AccountNotInitialized|3012|0xbc4/));
  }

  // ============================================================
  // TEST K: double close_receipt → second call fails
  //   First close succeeds and removes the PDA. Second close fails on
  //   AccountNotInitialized.
  // ============================================================
  console.log("\n[K] Double close_receipt → second call fails");
  {
    const depositor = Keypair.generate();
    await connection.confirmTransaction(
      await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)
    );
    const drop = await createDropWithReceipt(depositor, BigInt(0.02 * LAMPORTS_PER_SOL));

    const closeIx = buildCloseReceiptIx({
      leafBytes: drop.leafBytes,
      receipt: drop.receipt,
      depositorKey: depositor.publicKey,
    });
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(closeIx), [depositor]);
      console.log("    first close succeeded (expected)");
    } catch (e) {
      console.log("  [FAIL] K setup: first close should have succeeded:", e.message);
      fail++;
    }

    // Second close should fail
    const build = () => new Transaction().add(buildCloseReceiptIx({
      leafBytes: drop.leafBytes,
      receipt: drop.receipt,
      depositorKey: depositor.publicKey,
    }));
    build.signers = [depositor];
    record(await expectFail("K", build, /AccountNotInitialized|3012|0xbc4/));
  }

  console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
}

main().then(() => process.exit(0)).catch(e => {
  console.error("Fatal:", e);
  if (e.logs) e.logs.forEach(l => console.error(`  ${l}`));
  process.exit(1);
});
