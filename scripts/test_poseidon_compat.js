#!/usr/bin/env node
// Cross-compatibility test: circomlib Poseidon vs light-hasher Poseidon
//
// Computes Poseidon(1, 2) and Poseidon(0, 0) using circomlib (JS),
// then compares against light-hasher (Rust) output.
//
// The Rust side is tested via a small Rust program that we compile and run.

const { buildPoseidon } = require("circomlibjs");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("=== Poseidon Cross-Compatibility Test ===\n");

  // --- JS side (circomlib) ---
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  function hashToHex(inputs) {
    const h = poseidon(inputs.map(x => BigInt(x)));
    const val = F.toObject(h);
    return val.toString(16).padStart(64, "0");
  }

  const jsHash_0_0 = hashToHex([0, 0]);
  const jsHash_1_2 = hashToHex([1, 2]);
  const jsHash_single_0 = (() => {
    const h = poseidon([BigInt(0)]);
    return F.toObject(h).toString(16).padStart(64, "0");
  })();

  console.log("circomlib (JS):");
  console.log(`  Poseidon(0, 0) = ${jsHash_0_0}`);
  console.log(`  Poseidon(1, 2) = ${jsHash_1_2}`);
  console.log(`  Poseidon(0)    = ${jsHash_single_0}`);

  // --- Rust side (light-hasher) ---
  // Write a small Rust test program
  const rustDir = "/tmp/poseidon-compat-test";
  fs.mkdirSync(rustDir, { recursive: true });

  fs.writeFileSync(path.join(rustDir, "Cargo.toml"), `
[package]
name = "poseidon-compat-test"
version = "0.1.0"
edition = "2021"

[dependencies]
light-hasher = "4.0.0"
`);

  fs.mkdirSync(path.join(rustDir, "src"), { recursive: true });
  fs.writeFileSync(path.join(rustDir, "src/main.rs"), `
use light_hasher::{Hasher, Poseidon};

fn to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    // Poseidon(0, 0)
    let zero = [0u8; 32];
    let h_0_0 = Poseidon::hashv(&[&zero, &zero]).unwrap();
    println!("Poseidon(0, 0) = {}", to_hex(&h_0_0));

    // Poseidon(1, 2)
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut two = [0u8; 32];
    two[31] = 2;
    let h_1_2 = Poseidon::hashv(&[&one, &two]).unwrap();
    println!("Poseidon(1, 2) = {}", to_hex(&h_1_2));

    // Also test zero_bytes (used for Merkle tree initialization)
    let zero_bytes = Poseidon::zero_bytes();
    println!("zero_bytes[0]  = {}", to_hex(&zero_bytes[0]));
    println!("zero_bytes[1]  = {}", to_hex(&zero_bytes[1]));
}
`);

  console.log("\nCompiling Rust test...");
  try {
    execSync(`cd ${rustDir} && cargo build --release 2>&1`, { timeout: 120000 });
    const rustOutput = execSync(`${rustDir}/target/release/poseidon-compat-test 2>&1`, { timeout: 10000 }).toString().trim();

    console.log(`\nlight-hasher (Rust):`);
    const lines = rustOutput.split("\n");
    for (const line of lines) {
      console.log(`  ${line}`);
    }

    // Parse Rust output
    const rustHash_0_0 = lines.find(l => l.includes("Poseidon(0, 0)"))?.split("= ")[1]?.trim();
    const rustHash_1_2 = lines.find(l => l.includes("Poseidon(1, 2)"))?.split("= ")[1]?.trim();

    // Compare
    console.log("\n=== Comparison ===");

    const match_0_0 = jsHash_0_0 === rustHash_0_0;
    const match_1_2 = jsHash_1_2 === rustHash_1_2;

    console.log(`  Poseidon(0, 0): JS=${jsHash_0_0.slice(0, 16)}... Rust=${(rustHash_0_0 || "N/A").slice(0, 16)}... ${match_0_0 ? "MATCH ✓" : "MISMATCH ✗"}`);
    console.log(`  Poseidon(1, 2): JS=${jsHash_1_2.slice(0, 16)}... Rust=${(rustHash_1_2 || "N/A").slice(0, 16)}... ${match_1_2 ? "MATCH ✓" : "MISMATCH ✗"}`);

    if (match_0_0 && match_1_2) {
      console.log("\n  RESULT: Poseidon implementations are COMPATIBLE");
      console.log("  Circuit and on-chain program will produce matching hashes.");
    } else {
      console.log("\n  RESULT: Poseidon implementations are INCOMPATIBLE");
      console.log("  WARNING: Circuit and on-chain program use different hash functions!");
      console.log("  This MUST be resolved before integration will work.");

      // Check endianness
      if (jsHash_0_0 && rustHash_0_0) {
        const jsReversed = jsHash_0_0.match(/.{2}/g).reverse().join("");
        if (jsReversed === rustHash_0_0) {
          console.log("  NOTE: Values match with reversed byte order — this is an endianness issue.");
        }
      }

      process.exit(1);
    }
  } catch (e) {
    console.error("\nRust compilation/execution failed:", e.message);
    console.log("\nFalling back to JS-only output for manual comparison.");
    console.log("Run the Rust test manually to compare.");
    process.exit(1);
  }
}

main().catch(console.error);
