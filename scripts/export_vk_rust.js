#!/usr/bin/env node
// Converts snarkjs verification_key.json to Rust byte arrays for on-chain verification.
// Usage: node export_vk_rust.js ../circuits/build/verification_key.json

const fs = require("fs");
const path = require("path");

const vkPath = process.argv[2] || path.join(__dirname, "../circuits/build/verification_key.json");
const vk = JSON.parse(fs.readFileSync(vkPath, "utf8"));

// Convert a decimal string to a 32-byte big-endian array
function toBE32(decStr) {
  let hex = BigInt(decStr).toString(16).padStart(64, "0");
  const bytes = [];
  for (let i = 0; i < 64; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

// G1 point: [x, y] -> 64 bytes (x BE32 || y BE32)
function g1ToBytes(point) {
  return [...toBE32(point[0]), ...toBE32(point[1])];
}

// G2 point: [[x0, x1], [y0, y1]] -> 128 bytes (x1 BE32 || x0 BE32 || y1 BE32 || y0 BE32)
// Note: G2 encoding order is reversed per element pair for alt_bn128
function g2ToBytes(point) {
  return [
    ...toBE32(point[0][1]), ...toBE32(point[0][0]),
    ...toBE32(point[1][1]), ...toBE32(point[1][0]),
  ];
}

function formatBytes(bytes, indent = "    ") {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16).map(b => b.toString()).join(", ");
    lines.push(`${indent}${chunk},`);
  }
  return lines.join("\n");
}

const alpha_g1 = g1ToBytes(vk.vk_alpha_1);
const beta_g2 = g2ToBytes(vk.vk_beta_2);
const gamma_g2 = g2ToBytes(vk.vk_gamma_2);
const delta_g2 = g2ToBytes(vk.vk_delta_2);
const ic = vk.IC.map(p => g1ToBytes(p));

console.log(`// Auto-generated from verification_key.json`);
console.log(`// Circuit: DarkDrop V4 Claim (depth 20, ${vk.nPublic} public inputs)`);
console.log(`// DO NOT EDIT — regenerate with: node scripts/export_vk_rust.js`);
console.log(``);
console.log(`use groth16_solana::groth16::Groth16Verifyingkey;`);
console.log(``);
console.log(`pub const NR_PUBLIC_INPUTS: usize = ${vk.nPublic};`);
console.log(``);

console.log(`pub const VK_ALPHA_G1: [u8; 64] = [`);
console.log(formatBytes(alpha_g1));
console.log(`];`);
console.log(``);

console.log(`pub const VK_BETA_G2: [u8; 128] = [`);
console.log(formatBytes(beta_g2));
console.log(`];`);
console.log(``);

console.log(`pub const VK_GAMMA_G2: [u8; 128] = [`);
console.log(formatBytes(gamma_g2));
console.log(`];`);
console.log(``);

console.log(`pub const VK_DELTA_G2: [u8; 128] = [`);
console.log(formatBytes(delta_g2));
console.log(`];`);
console.log(``);

// IC points (NR_PUBLIC_INPUTS + 1)
console.log(`pub const IC: [[u8; 64]; ${ic.length}] = [`);
for (let i = 0; i < ic.length; i++) {
  console.log(`    // IC[${i}]`);
  console.log(`    [`);
  console.log(formatBytes(ic[i], "        "));
  console.log(`    ],`);
}
console.log(`];`);
console.log(``);

console.log(`pub fn verifying_key() -> Groth16Verifyingkey<'static> {`);
console.log(`    Groth16Verifyingkey {`);
console.log(`        nr_pubinputs: NR_PUBLIC_INPUTS,`);
console.log(`        vk_alpha_g1: VK_ALPHA_G1,`);
console.log(`        vk_beta_g2: VK_BETA_G2,`);
console.log(`        vk_gamme_g2: VK_GAMMA_G2,`);
console.log(`        vk_delta_g2: VK_DELTA_G2,`);
console.log(`        vk_ic: &IC,`);
console.log(`    }`);
console.log(`}`);
