#!/usr/bin/env node
// Generate Poseidon zero hashes for the on-chain Merkle tree.
// zeros[0] = 0
// zeros[i+1] = Poseidon(zeros[i], zeros[i])
//
// Outputs Rust code for state.rs

const { buildPoseidon } = require("circomlibjs");

const DEPTH = 20;

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const zeros = [BigInt(0)];
  for (let i = 0; i < DEPTH; i++) {
    const h = poseidon([zeros[i], zeros[i]]);
    zeros.push(F.toObject(h));
  }

  // Convert BigInt to 32-byte big-endian array
  function toBE32(val) {
    const hex = val.toString(16).padStart(64, "0");
    const bytes = [];
    for (let i = 0; i < 64; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
  }

  function formatBytes(bytes) {
    const chunks = [];
    for (let i = 0; i < bytes.length; i += 8) {
      chunks.push(bytes.slice(i, i + 8).map(b => b.toString().padStart(3, " ")).join(", "));
    }
    return chunks.join(",\n        ");
  }

  // Print verification values
  console.error("Zero hash values (decimal):");
  for (let i = 0; i <= DEPTH; i++) {
    console.error(`  zeros[${i.toString().padStart(2)}] = ${zeros[i].toString().slice(0, 30)}...`);
  }

  // Output Rust code
  console.log("// Auto-generated Poseidon zero hashes for Merkle tree initialization.");
  console.log("// zeros[0] = 0");
  console.log("// zeros[i+1] = Poseidon(zeros[i], zeros[i])");
  console.log("// Generated with circomlib's Poseidon (same as circuit).");
  console.log("// DO NOT EDIT — regenerate with: node scripts/generate_zero_hashes.js");
  console.log("");
  console.log(`pub const ZERO_HASHES: [[u8; 32]; ${DEPTH + 1}] = [`);

  for (let i = 0; i <= DEPTH; i++) {
    const bytes = toBE32(zeros[i]);
    console.log(`    // zeros[${i}]${i === 0 ? " = 0" : ` = Poseidon(zeros[${i-1}], zeros[${i-1}])`}`);
    console.log(`    [`);
    console.log(`        ${formatBytes(bytes)},`);
    console.log(`    ],`);
  }

  console.log("];");
}

main().catch(console.error);
