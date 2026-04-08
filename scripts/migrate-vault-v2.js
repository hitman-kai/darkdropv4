#!/usr/bin/env node
/**
 * One-time migration: call migrate_vault to realloc the Vault account
 * with total_deposited and total_withdrawn fields.
 */

const { Connection, Keypair, PublicKey, TransactionMessage, VersionedTransaction } = require('@solana/web3.js');
const fs = require('fs');
const path = require('path');

const PROGRAM_ID = new PublicKey('GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU');
const RPC_URL = process.env.RPC_URL || 'https://api.devnet.solana.com';

// migrate_vault discriminator: sha256("global:migrate_vault")[0..8]
const crypto = require('crypto');
const disc = crypto.createHash('sha256').update('global:migrate_vault').digest().slice(0, 8);

async function main() {
  const conn = new Connection(RPC_URL, 'confirmed');

  const keyPath = path.join(require('os').homedir(), '.config/solana/id.json');
  const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(keyPath, 'utf8'))));
  console.log('Authority:', payer.publicKey.toBase58());

  const [vault] = PublicKey.findProgramAddressSync([Buffer.from('vault')], PROGRAM_ID);
  console.log('Vault PDA:', vault.toBase58());

  const ix = {
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: new PublicKey('11111111111111111111111111111111'), isSigner: false, isWritable: false },
    ],
    data: disc,
  };

  const { blockhash } = await conn.getLatestBlockhash();
  const msg = new TransactionMessage({
    payerKey: payer.publicKey,
    recentBlockhash: blockhash,
    instructions: [ix],
  }).compileToV0Message();

  const tx = new VersionedTransaction(msg);
  tx.sign([payer]);

  const sig = await conn.sendRawTransaction(tx.serialize());
  console.log('TX:', sig);

  const result = await conn.confirmTransaction(sig, 'confirmed');
  if (result.value.err) {
    console.error('Migration failed:', result.value.err);
    process.exit(1);
  }

  console.log('Vault migrated successfully!');
}

main().catch(e => { console.error(e); process.exit(1); });
