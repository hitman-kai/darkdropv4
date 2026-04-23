"use client";

import { useEffect, useState, useCallback } from "react";
import { useWallet, useConnection } from "@solana/wallet-adapter-react";
import { Connection, Transaction } from "@solana/web3.js";

import {
  initPoseidon,
  nullifierHash as computeNullifierHash,
  bigintToBytes32BE,
} from "@/lib/crypto";
import {
  REVOKE_TIMEOUT_SECONDS,
  StoredReceipt,
  hexToBytes,
  hex32ToBigint,
  listLocalReceipts,
  removeLocalReceipt,
  fetchReceipt,
} from "@/lib/receipt";
import { getNullifierPDA } from "@/lib/vault";
import { buildRevokeDropIx, buildCloseReceiptIx } from "@/lib/revoke";

type Status = "pending" | "revokable" | "claimed" | "resolved" | "unknown";

interface EnrichedReceipt {
  stored: StoredReceipt;
  status: Status;
  onChainCreatedAt: number | null;
  revokableAt: number; // unix seconds — when revoke becomes available
}

async function enrichReceipt(
  connection: Connection,
  stored: StoredReceipt
): Promise<EnrichedReceipt> {
  const leafBytes = hexToBytes(stored.leafHex);
  const receipt = await fetchReceipt(connection, leafBytes);

  if (!receipt) {
    // Receipt PDA is gone — already revoked or closed.
    return {
      stored,
      status: "resolved",
      onChainCreatedAt: null,
      revokableAt: stored.createdAt + REVOKE_TIMEOUT_SECONDS,
    };
  }

  // Check whether the nullifier PDA exists. If yes, the drop was claimed.
  const nullifierBig = hex32ToBigint(stored.nullifierHex);
  const nullHashBytes = bigintToBytes32BE(computeNullifierHash(nullifierBig));
  const [nullPda] = getNullifierPDA(nullHashBytes);
  const nullInfo = await connection.getAccountInfo(nullPda);

  const revokableAt = receipt.createdAt + REVOKE_TIMEOUT_SECONDS;

  if (nullInfo) {
    return { stored, status: "claimed", onChainCreatedAt: receipt.createdAt, revokableAt };
  }

  const now = Math.floor(Date.now() / 1000);
  const status: Status = now >= revokableAt ? "revokable" : "pending";
  return { stored, status, onChainCreatedAt: receipt.createdAt, revokableAt };
}

function formatCountdown(secondsRemaining: number): string {
  if (secondsRemaining <= 0) return "ready";
  const d = Math.floor(secondsRemaining / 86400);
  const h = Math.floor((secondsRemaining % 86400) / 3600);
  const m = Math.floor((secondsRemaining % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function shortLeaf(hex: string): string {
  return hex.slice(0, 8) + "…" + hex.slice(-6);
}

export default function ManageDropsPage() {
  const { publicKey, sendTransaction } = useWallet();
  const { connection } = useConnection();
  const [rows, setRows] = useState<EnrichedReceipt[]>([]);
  const [loading, setLoading] = useState(false);
  const [busyLeaf, setBusyLeaf] = useState<string | null>(null);
  const [notice, setNotice] = useState<string>("");
  const [error, setError] = useState<string>("");

  const refresh = useCallback(async () => {
    if (!publicKey) {
      setRows([]);
      return;
    }
    setLoading(true);
    setError("");
    try {
      await initPoseidon();
      const stored = listLocalReceipts(publicKey.toBase58());
      const enriched = await Promise.all(
        stored.map((s) => enrichReceipt(connection, s))
      );
      setRows(enriched);
    } catch (e: any) {
      setError(e.message || "Failed to load receipts");
    } finally {
      setLoading(false);
    }
  }, [connection, publicKey]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleRevoke = async (row: EnrichedReceipt) => {
    if (!publicKey || !sendTransaction) return;
    setBusyLeaf(row.stored.leafHex);
    setError("");
    setNotice("");
    try {
      await initPoseidon();
      const leafBytes = hexToBytes(row.stored.leafHex);
      const secret = hex32ToBigint(row.stored.secretHex);
      const nullifier = hex32ToBigint(row.stored.nullifierHex);
      const blinding = hex32ToBigint(row.stored.blindingHex);
      const nullHashBytes = bigintToBytes32BE(computeNullifierHash(nullifier));

      const ix = buildRevokeDropIx({
        depositor: publicKey,
        leaf: leafBytes,
        nullifierHashBytes: nullHashBytes,
        secret,
        nullifier,
        blinding,
      });

      const tx = new Transaction().add(ix);
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");
      setNotice(`Revoked ${shortLeaf(row.stored.leafHex)} — ${sig.slice(0, 8)}…`);
      await refresh();
    } catch (e: any) {
      setError(e.message || "Revoke failed");
    } finally {
      setBusyLeaf(null);
    }
  };

  const handleClose = async (row: EnrichedReceipt) => {
    if (!publicKey || !sendTransaction) return;
    setBusyLeaf(row.stored.leafHex);
    setError("");
    setNotice("");
    try {
      const leafBytes = hexToBytes(row.stored.leafHex);
      const ix = buildCloseReceiptIx({ depositor: publicKey, leaf: leafBytes });
      const tx = new Transaction().add(ix);
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");
      setNotice(`Closed ${shortLeaf(row.stored.leafHex)} — rent recovered`);
      await refresh();
    } catch (e: any) {
      setError(e.message || "Close failed");
    } finally {
      setBusyLeaf(null);
    }
  };

  const handleForget = (row: EnrichedReceipt) => {
    if (!publicKey) return;
    removeLocalReceipt(publicKey.toBase58(), row.stored.leafHex);
    refresh();
  };

  const now = Math.floor(Date.now() / 1000);

  return (
    <div className="mx-auto w-full max-w-3xl px-4 sm:px-6 pb-20" style={{ paddingTop: "80px" }}>
      <div className="mb-8">
        <p className="mb-2 font-mono text-[9px] tracking-[0.3em] text-[var(--accent-dim)]">
          MANAGE // RECEIPTS
        </p>
        <h1 className="font-mono text-[clamp(24px,4vw,36px)] font-light leading-[1.15] text-[var(--text)]">
          Your drops.
        </h1>
        <p className="mt-3 text-xs leading-relaxed text-[rgba(224,224,224,0.45)]">
          Revoke unclaimed drops after the 30-day time-lock, or recover rent from drops that were already claimed.
        </p>
      </div>

      {!publicKey && (
        <div className="arcade-panel">
          <div className="arcade-panel-body text-center text-sm text-[rgba(224,224,224,0.4)]">
            Connect your wallet to see your receipts.
          </div>
        </div>
      )}

      {publicKey && (
        <>
          {notice && (
            <div className="mb-4 border-2 border-[rgba(0,255,65,0.25)] bg-[rgba(0,255,65,0.04)] px-5 py-3">
              <p className="text-xs text-[var(--accent)]">{notice}</p>
            </div>
          )}
          {error && (
            <div className="mb-4 border-2 border-[rgba(255,0,68,0.3)] bg-[rgba(255,0,68,0.04)] px-5 py-3">
              <p className="text-xs text-[var(--danger)] font-semibold">{error}</p>
            </div>
          )}

          <div className="mb-4 flex items-center justify-between">
            <p className="font-mono text-[9px] tracking-[0.2em] text-[rgba(224,224,224,0.35)]">
              {rows.length === 0 ? "NO RECEIPTS" : `${rows.length} RECEIPT${rows.length === 1 ? "" : "S"}`}
            </p>
            <button
              onClick={refresh}
              disabled={loading}
              className="arcade-btn-ghost px-3 py-1.5 font-mono text-[9px] tracking-[0.15em]"
            >
              {loading ? "..." : "REFRESH"}
            </button>
          </div>

          {rows.length === 0 && !loading && (
            <div className="arcade-panel">
              <div className="arcade-panel-body text-center text-xs text-[rgba(224,224,224,0.4)]">
                No receipts stored in this browser. Receipts are created when you enable the revoke option on a drop.
              </div>
            </div>
          )}

          <div className="space-y-3">
            {rows.map((row) => {
              const secondsToRevoke = Math.max(0, row.revokableAt - now);
              const amountSol = (Number(row.stored.amountLamports) / 1e9).toFixed(5);
              return (
                <div key={row.stored.leafHex} className="arcade-panel">
                  <div className="arcade-panel-header justify-between">
                    <div className="flex items-center gap-3">
                      <span className="arcade-dot" />
                      <span className="font-mono text-[9px] tracking-[0.18em] text-[rgba(224,224,224,0.5)]">
                        {shortLeaf(row.stored.leafHex)}
                      </span>
                    </div>
                    <span className={`font-mono text-[8px] tracking-[0.14em] ${
                      row.status === "revokable" ? "text-[var(--accent)]" :
                      row.status === "claimed" ? "text-[rgba(255,200,0,0.7)]" :
                      row.status === "resolved" ? "text-[rgba(224,224,224,0.35)]" :
                      "text-[rgba(224,224,224,0.5)]"
                    }`}>
                      {row.status === "pending" && `LOCKED · ${formatCountdown(secondsToRevoke)}`}
                      {row.status === "revokable" && "REVOKABLE"}
                      {row.status === "claimed" && "CLAIMED · ORPHAN"}
                      {row.status === "resolved" && "RESOLVED"}
                      {row.status === "unknown" && "UNKNOWN"}
                    </span>
                  </div>
                  <div className="arcade-panel-body space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-[rgba(224,224,224,0.4)]">AMOUNT</span>
                      <span className="font-mono text-[var(--accent)]">{amountSol} SOL</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-[rgba(224,224,224,0.4)]">LEAF INDEX</span>
                      <span className="font-mono text-[rgba(224,224,224,0.7)]">#{row.stored.leafIndex}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-[rgba(224,224,224,0.4)]">CREATED</span>
                      <span className="font-mono text-[rgba(224,224,224,0.7)]">
                        {new Date(row.stored.createdAt * 1000).toLocaleString()}
                      </span>
                    </div>

                    <div className="flex flex-wrap gap-2 pt-2">
                      {row.status === "revokable" && (
                        <button
                          onClick={() => handleRevoke(row)}
                          disabled={busyLeaf === row.stored.leafHex}
                          className="arcade-btn-primary px-4 py-2 font-mono text-[9px] tracking-[0.15em]"
                        >
                          {busyLeaf === row.stored.leafHex ? "..." : "REVOKE"}
                        </button>
                      )}
                      {row.status === "pending" && (
                        <button
                          disabled
                          className="arcade-btn-ghost px-4 py-2 font-mono text-[9px] tracking-[0.15em] opacity-40 !cursor-not-allowed"
                        >
                          REVOKE IN {formatCountdown(secondsToRevoke)}
                        </button>
                      )}
                      {row.status === "claimed" && (
                        <button
                          onClick={() => handleClose(row)}
                          disabled={busyLeaf === row.stored.leafHex}
                          className="arcade-btn-primary px-4 py-2 font-mono text-[9px] tracking-[0.15em]"
                        >
                          {busyLeaf === row.stored.leafHex ? "..." : "RECOVER RENT"}
                        </button>
                      )}
                      {row.status === "resolved" && (
                        <button
                          onClick={() => handleForget(row)}
                          className="arcade-btn-ghost px-4 py-2 font-mono text-[9px] tracking-[0.15em]"
                        >
                          REMOVE FROM LIST
                        </button>
                      )}
                      {row.stored.txSig && (
                        <a
                          href={`https://solscan.io/tx/${row.stored.txSig}?cluster=devnet`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="arcade-btn-ghost px-4 py-2 font-mono text-[9px] tracking-[0.15em]"
                        >
                          VIEW DEPOSIT
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
