/**
 * Wallet-adapter TX send with bounded retry on the specific transient
 * errors that surface during the `migrate_schema_v2` deploy→migration
 * window (~1–2 seconds). Retries up to 3 times with 1s/2s/4s backoff.
 *
 * The migration window flips the MerkleTree / NotePoolTree account layout
 * from 1680 bytes (ROOT_HISTORY_SIZE=30) to 8912 bytes (256). Between the
 * program redeploy and the migrate_schema_v2 TX landing, the on-chain
 * program tries to deserialize the old-size account into the new struct
 * and fails with `AccountDidNotDeserialize`. We catch that specifically,
 * not generic failures — fast-fail on anything unknown.
 */

import type { Connection, Transaction, VersionedTransaction } from "@solana/web3.js";
import type { WalletContextState } from "@solana/wallet-adapter-react";

const TRANSIENT_LOG_PATTERNS = [
  /AccountDidNotDeserialize/i,
  /Failed to deserialize the account/i,
];

export interface SendWithRetryArgs {
  wallet: Pick<WalletContextState, "sendTransaction">;
  connection: Connection;
  transaction: Transaction | VersionedTransaction;
  attempts?: number;
  onRetry?: (attempt: number, reason: string) => void;
}

export class TransientChainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransientChainError";
  }
}

export async function sendWithRetry({
  wallet,
  connection,
  transaction,
  attempts = 3,
  onRetry,
}: SendWithRetryArgs): Promise<string> {
  if (!wallet.sendTransaction) throw new Error("Wallet not connected");

  let lastErr: unknown = null;

  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const sig = await wallet.sendTransaction(transaction, connection);
      const conf = await connection.confirmTransaction(sig, "confirmed");

      if (conf.value.err) {
        const transient = await isTransientFailure(connection, sig);
        if (transient && attempt < attempts - 1) {
          onRetry?.(attempt + 1, "chain migration in progress");
          await delay(1000 * Math.pow(2, attempt));
          continue;
        }
        throw new Error(`TX failed on-chain: ${JSON.stringify(conf.value.err)}`);
      }

      return sig;
    } catch (e) {
      lastErr = e;
      const msg = String((e as Error)?.message || e);
      const transientByMessage = TRANSIENT_LOG_PATTERNS.some((p) => p.test(msg));
      if (transientByMessage && attempt < attempts - 1) {
        onRetry?.(attempt + 1, "chain migration in progress");
        await delay(1000 * Math.pow(2, attempt));
        continue;
      }
      throw e;
    }
  }

  throw lastErr instanceof Error
    ? lastErr
    : new TransientChainError("Exhausted retries");
}

async function isTransientFailure(
  connection: Connection,
  signature: string
): Promise<boolean> {
  try {
    const tx = await connection.getTransaction(signature, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const logs = tx?.meta?.logMessages?.join("\n") || "";
    return TRANSIENT_LOG_PATTERNS.some((p) => p.test(logs));
  } catch {
    return false;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
