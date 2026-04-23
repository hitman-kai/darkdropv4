#!/usr/bin/env node
/**
 * DarkDrop V4 — Account Size Pre-Flight
 *
 * Dumps the on-chain byte size of the Vault, MerkleTree, and NotePoolTree
 * accounts so migrate-schema-v2.js has a known-good baseline to assert
 * against before reallocating. Writes scripts/migration-baseline.json.
 *
 * Run:
 *   RPC_URL=https://api.devnet.solana.com node scripts/dump-account-sizes.js
 */

const { Connection, PublicKey } = require("@solana/web3.js");
const fs = require("fs");
const path = require("path");

const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey(
  process.env.PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU"
);

function pda(seeds) {
  return PublicKey.findProgramAddressSync(seeds, PROGRAM_ID)[0];
}

async function main() {
  const conn = new Connection(RPC_URL, "confirmed");

  const vault = pda([Buffer.from("vault")]);
  const merkleTree = pda([Buffer.from("merkle_tree"), vault.toBytes()]);
  const notePoolTree = pda([Buffer.from("note_pool_tree"), vault.toBytes()]);

  const targets = [
    { name: "vault", pubkey: vault },
    { name: "merkle_tree", pubkey: merkleTree },
    { name: "note_pool_tree", pubkey: notePoolTree },
  ];

  const baseline = {
    program_id: PROGRAM_ID.toBase58(),
    cluster: RPC_URL.includes("devnet") ? "devnet" : "unknown",
    captured_at: new Date().toISOString(),
    accounts: {},
  };

  for (const t of targets) {
    const info = await conn.getAccountInfo(t.pubkey);
    if (!info) {
      baseline.accounts[t.name] = { address: t.pubkey.toBase58(), size: null, lamports: null, present: false };
      console.log(`${t.name.padEnd(15)} ${t.pubkey.toBase58().padEnd(44)} NOT FOUND`);
      continue;
    }
    baseline.accounts[t.name] = {
      address: t.pubkey.toBase58(),
      size: info.data.length,
      lamports: info.lamports,
      present: true,
    };
    console.log(
      `${t.name.padEnd(15)} ${t.pubkey.toBase58().padEnd(44)} ${String(info.data.length).padStart(5)} bytes · ${info.lamports} lamports`
    );
  }

  const outPath = path.join(__dirname, "migration-baseline.json");
  fs.writeFileSync(outPath, JSON.stringify(baseline, null, 2) + "\n");
  console.log(`\nWrote ${outPath}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
