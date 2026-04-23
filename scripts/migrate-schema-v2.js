#!/usr/bin/env node
/**
 * DarkDrop V4 — schema v2 migration runner.
 *
 * Reallocates the on-chain MerkleTreeAccount and NotePoolTree from
 * ROOT_HISTORY_SIZE=30 (1680 bytes) to ROOT_HISTORY_SIZE=256 (8912 bytes).
 * Idempotent: if both trees are already at 8912 bytes, exits cleanly.
 *
 * Pre-flight: verifies current sizes against scripts/migration-baseline.json.
 * If reality has drifted, aborts loudly rather than migrating blindly.
 *
 * Run (after `solana program deploy` of the new binary):
 *   RPC_URL=https://api.devnet.solana.com \
 *   KEYPAIR=~/.config/solana/id.json \
 *   node scripts/migrate-schema-v2.js
 */

const {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} = require("@solana/web3.js");
const fs = require("fs");
const path = require("path");
const os = require("os");

const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey(
  process.env.PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU"
);
const KEYPAIR_PATH =
  process.env.KEYPAIR || path.join(os.homedir(), ".config/solana/id.json");

const OLD_TREE_SIZE = 1680;
const NEW_TREE_SIZE = 8912;
const MIGRATE_DISC = Buffer.from([169, 82, 231, 138, 226, 218, 110, 237]);

function pda(seeds) {
  return PublicKey.findProgramAddressSync(seeds, PROGRAM_ID)[0];
}

async function main() {
  const baselinePath = path.join(__dirname, "migration-baseline.json");
  if (!fs.existsSync(baselinePath)) {
    throw new Error(
      `Missing ${baselinePath}. Run scripts/dump-account-sizes.js first.`
    );
  }
  const baseline = JSON.parse(fs.readFileSync(baselinePath, "utf8"));
  if (baseline.program_id !== PROGRAM_ID.toBase58()) {
    throw new Error(
      `Baseline program_id (${baseline.program_id}) != expected (${PROGRAM_ID.toBase58()})`
    );
  }

  const conn = new Connection(RPC_URL, "confirmed");
  const authority = Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH, "utf8")))
  );

  const vault = pda([Buffer.from("vault")]);
  const merkleTree = pda([Buffer.from("merkle_tree"), vault.toBytes()]);
  const notePoolTree = pda([Buffer.from("note_pool_tree"), vault.toBytes()]);

  console.log("=== schema v2 migration ===");
  console.log(`  RPC          ${RPC_URL}`);
  console.log(`  Program      ${PROGRAM_ID.toBase58()}`);
  console.log(`  Authority    ${authority.publicKey.toBase58()}`);
  console.log(`  Vault        ${vault.toBase58()}`);
  console.log(`  MerkleTree   ${merkleTree.toBase58()}`);
  console.log(`  NotePoolTree ${notePoolTree.toBase58()}`);

  // Read current sizes.
  const [mtInfo, nptInfo] = await Promise.all([
    conn.getAccountInfo(merkleTree),
    conn.getAccountInfo(notePoolTree),
  ]);
  if (!mtInfo) throw new Error("MerkleTree account not found on-chain");
  if (!nptInfo) throw new Error("NotePoolTree account not found on-chain");

  const mtSize = mtInfo.data.length;
  const nptSize = nptInfo.data.length;
  console.log(`\n  merkle_tree       before: ${mtSize} bytes`);
  console.log(`  note_pool_tree    before: ${nptSize} bytes`);

  // Assert against baseline. Accept "already migrated" silently.
  const allowed = new Set([OLD_TREE_SIZE, NEW_TREE_SIZE]);
  if (!allowed.has(mtSize) || !allowed.has(nptSize)) {
    throw new Error(
      `Unexpected tree sizes (mt=${mtSize} npt=${nptSize}); expected ${OLD_TREE_SIZE} or ${NEW_TREE_SIZE}`
    );
  }
  const baselineMt = baseline.accounts.merkle_tree?.size;
  const baselineNpt = baseline.accounts.note_pool_tree?.size;
  if (baselineMt !== OLD_TREE_SIZE || baselineNpt !== OLD_TREE_SIZE) {
    console.warn(
      `  warning: baseline sizes (mt=${baselineMt}, npt=${baselineNpt}) do not match OLD_TREE_SIZE=${OLD_TREE_SIZE}. Proceeding anyway — current live sizes (${mtSize}, ${nptSize}) are authoritative.`
    );
  }
  if (mtSize === NEW_TREE_SIZE && nptSize === NEW_TREE_SIZE) {
    console.log("\n  both trees already at NEW_TREE_SIZE — migration already applied, exiting cleanly.");
    return;
  }

  // Estimate rent diff we'll be paying.
  const rent = await conn.getMinimumBalanceForRentExemption(NEW_TREE_SIZE);
  const currentRent = mtInfo.lamports; // same for both trees at OLD_TREE_SIZE
  const diff = Math.max(0, rent - currentRent);
  console.log(
    `\n  rent to top up per tree: ~${(diff / LAMPORTS_PER_SOL).toFixed(6)} SOL`
  );

  // Build migrate_schema_v2 instruction.
  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: false },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: notePoolTree, isSigner: false, isWritable: true },
      { pubkey: authority.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: MIGRATE_DISC,
  });

  const tx = new Transaction().add(ix);
  console.log("\n  submitting migrate_schema_v2 TX...");
  const sig = await sendAndConfirmTransaction(conn, tx, [authority], {
    commitment: "confirmed",
  });
  console.log(`  TX: ${sig}`);

  // Verify post-state.
  const [mtAfter, nptAfter] = await Promise.all([
    conn.getAccountInfo(merkleTree),
    conn.getAccountInfo(notePoolTree),
  ]);
  console.log(`\n  merkle_tree       after:  ${mtAfter.data.length} bytes`);
  console.log(`  note_pool_tree    after:  ${nptAfter.data.length} bytes`);

  if (mtAfter.data.length !== NEW_TREE_SIZE || nptAfter.data.length !== NEW_TREE_SIZE) {
    throw new Error(
      `Post-migration sizes wrong (mt=${mtAfter.data.length}, npt=${nptAfter.data.length}); expected ${NEW_TREE_SIZE}`
    );
  }
  console.log("\n  ok: schema v2 migration applied.");
}

main().catch((e) => {
  console.error("\nmigration failed:", e.message || e);
  if (e.logs) e.logs.forEach((l) => console.error(`  ${l}`));
  process.exit(1);
});
