"use client";

import { useEffect, useState, useCallback } from "react";
import { useWallet, useConnection } from "@solana/wallet-adapter-react";
import { Connection, PublicKey, Transaction } from "@solana/web3.js";

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
import { getNullifierPDA, getVaultPDA, getMerkleTreePDA } from "@/lib/vault";
import { buildRevokeDropIx, buildCloseReceiptIx } from "@/lib/revoke";
import { CURRENT_ROOT_HISTORY_SIZE, readTreeNextIndex } from "@/lib/merkle";
import {
  StealthRecord,
  listStealthForOwner,
  recoverKeypair,
  sweepStealth,
  deleteStealth,
} from "@/lib/stealth";

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

interface SnapshotStaleness {
  depositsAfter: number;
  remaining: number;
  level: "ok" | "warn" | "expired";
}

// Warn when the claim code's embedded tree snapshot is within this many
// deposits of rotating out of the on-chain root_history buffer.
const STALENESS_WARN_WINDOW = 64;

function computeStaleness(
  leafIndex: number,
  treeNextIndex: number | null
): SnapshotStaleness | null {
  if (treeNextIndex === null) return null;
  const depositsAfter = Math.max(0, treeNextIndex - 1 - leafIndex);
  const remaining = CURRENT_ROOT_HISTORY_SIZE - depositsAfter;
  let level: SnapshotStaleness["level"] = "ok";
  if (remaining <= 0) level = "expired";
  else if (remaining <= STALENESS_WARN_WINDOW) level = "warn";
  return { depositsAfter, remaining, level };
}

export default function ManageDropsPage() {
  const { publicKey, sendTransaction } = useWallet();
  const { connection } = useConnection();
  const [rows, setRows] = useState<EnrichedReceipt[]>([]);
  const [treeNextIndex, setTreeNextIndex] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [busyLeaf, setBusyLeaf] = useState<string | null>(null);
  const [notice, setNotice] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [stealthRows, setStealthRows] = useState<{ record: StealthRecord; balance: number }[]>([]);
  const [busyStealth, setBusyStealth] = useState<string | null>(null);

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

      // Fetch merkle tree next_index once for the whole page; used to
      // compute snapshot staleness per-row.
      const [vault] = getVaultPDA();
      const [merkleTree] = getMerkleTreePDA(vault);
      const treePromise = connection
        .getAccountInfo(merkleTree)
        .then((info) => (info ? readTreeNextIndex(info.data) : null))
        .catch(() => null);

      // Stealth records owned by this wallet, plus their on-chain balances.
      const stealthRecords = listStealthForOwner(publicKey);
      const stealthPromise = Promise.all(
        stealthRecords.map(async (record) => {
          try {
            const balance = await connection.getBalance(new PublicKey(record.pubkey));
            return { record, balance };
          } catch {
            return { record, balance: 0 };
          }
        })
      );

      const [enriched, nextIdx, stealthLoaded] = await Promise.all([
        Promise.all(stored.map((s) => enrichReceipt(connection, s))),
        treePromise,
        stealthPromise,
      ]);
      setRows(enriched);
      setTreeNextIndex(nextIdx);
      setStealthRows(stealthLoaded);
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

  const handleSweep = async (entry: { record: StealthRecord; balance: number }) => {
    if (!publicKey) return;
    setBusyStealth(entry.record.pubkey);
    setError("");
    setNotice("");
    try {
      const keypair = recoverKeypair(entry.record);
      const { signature, lamports } = await sweepStealth(
        keypair,
        publicKey,
        connection
      );
      await connection.confirmTransaction(signature, "confirmed");
      const sweptSol = (lamports / 1e9).toFixed(5);
      setNotice(`Swept ${sweptSol} SOL from stealth ${entry.record.pubkey.slice(0, 8)}… — ${signature.slice(0, 8)}…`);
      // After successful sweep, the stealth account is empty. Drop it
      // from local storage so the list doesn't grow unbounded.
      deleteStealth(entry.record.pubkey);
      await refresh();
    } catch (e: any) {
      setError(e.message || "Sweep failed");
    } finally {
      setBusyStealth(null);
    }
  };

  const handleForgetStealth = (record: StealthRecord) => {
    deleteStealth(record.pubkey);
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

          {/* Stealth addresses (recipient-side claims) */}
          {stealthRows.length > 0 && (
            <div className="mb-6">
              <p className="mb-3 font-mono text-[9px] tracking-[0.2em] text-[rgba(224,224,224,0.35)]">
                {stealthRows.length} STEALTH ADDRESS{stealthRows.length === 1 ? "" : "ES"}
              </p>
              <div className="space-y-3">
                {stealthRows.map((entry) => {
                  const balanceSol = (entry.balance / 1e9).toFixed(5);
                  const empty = entry.balance < 6000; // below sweep fee floor
                  return (
                    <div key={entry.record.pubkey} className="arcade-panel">
                      <div className="arcade-panel-header justify-between">
                        <div className="flex items-center gap-3">
                          <span className="arcade-dot" />
                          <span className="font-mono text-[9px] tracking-[0.18em] text-[rgba(224,224,224,0.5)]">
                            {entry.record.pubkey.slice(0, 8) + "…" + entry.record.pubkey.slice(-6)}
                          </span>
                        </div>
                        <span className={`font-mono text-[8px] tracking-[0.14em] ${
                          empty ? "text-[rgba(224,224,224,0.35)]" : "text-[var(--accent)]"
                        }`}>
                          {empty ? "EMPTY" : "FUNDED"}
                        </span>
                      </div>
                      <div className="arcade-panel-body space-y-2">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-[rgba(224,224,224,0.4)]">BALANCE</span>
                          <span className="font-mono text-[var(--accent)]">{balanceSol} SOL</span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-[rgba(224,224,224,0.4)]">CLAIMED</span>
                          <span className="font-mono text-[rgba(224,224,224,0.7)]">
                            {new Date(entry.record.createdAt * 1000).toLocaleString()}
                          </span>
                        </div>
                        <p className="break-all font-mono text-[9px] leading-relaxed text-[rgba(224,224,224,0.35)]">
                          {entry.record.pubkey}
                        </p>
                        <div className="flex flex-wrap gap-2 pt-2">
                          {!empty && (
                            <button
                              onClick={() => handleSweep(entry)}
                              disabled={busyStealth === entry.record.pubkey}
                              className="arcade-btn-primary px-4 py-2 font-mono text-[9px] tracking-[0.15em]"
                            >
                              {busyStealth === entry.record.pubkey ? "..." : "SWEEP TO MAIN WALLET"}
                            </button>
                          )}
                          {empty && (
                            <button
                              onClick={() => handleForgetStealth(entry.record)}
                              className="arcade-btn-ghost px-4 py-2 font-mono text-[9px] tracking-[0.15em]"
                            >
                              REMOVE FROM LIST
                            </button>
                          )}
                          <a
                            href={`https://solscan.io/account/${entry.record.pubkey}?cluster=devnet`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="arcade-btn-ghost px-4 py-2 font-mono text-[9px] tracking-[0.15em]"
                          >
                            VIEW ON SOLSCAN
                          </a>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
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
              const staleness = computeStaleness(row.stored.leafIndex, treeNextIndex);
              const showStaleness =
                staleness !== null &&
                (row.status === "pending" || row.status === "revokable");
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

                    {showStaleness && staleness && (
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-[rgba(224,224,224,0.4)]">CLAIM WINDOW</span>
                        <span className={`font-mono ${
                          staleness.level === "expired" ? "text-[var(--danger)]" :
                          staleness.level === "warn" ? "text-[rgba(255,200,0,0.85)]" :
                          "text-[rgba(224,224,224,0.7)]"
                        }`}>
                          {staleness.level === "expired"
                            ? "EXPIRED — RECIPIENT CAN NO LONGER CLAIM"
                            : `${staleness.remaining} DEPOSITS LEFT`}
                        </span>
                      </div>
                    )}

                    {showStaleness && staleness?.level === "warn" && (
                      <p className="text-[10px] leading-relaxed text-[rgba(255,200,0,0.55)]">
                        Claim code&apos;s snapshot rotates out of on-chain root history soon. Ask the recipient to claim promptly, or revoke after the time-lock.
                      </p>
                    )}
                    {showStaleness && staleness?.level === "expired" && (
                      <p className="text-[10px] leading-relaxed text-[rgba(255,0,68,0.6)]">
                        The claim code can no longer verify on-chain. Wait out the 30-day lock and revoke to reclaim the SOL.
                      </p>
                    )}

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
