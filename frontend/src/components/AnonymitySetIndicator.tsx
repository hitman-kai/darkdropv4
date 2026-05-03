"use client";

import { useEffect, useState } from "react";
import { useConnection } from "@solana/wallet-adapter-react";
import { getVaultPDA, getMerkleTreePDA } from "@/lib/vault";
import { getNotePoolTreePDA } from "@/lib/note-pool";
import { readTreeNextIndex } from "@/lib/merkle";

interface PoolStats {
  deposits: number;
  poolNotes: number;
}

/**
 * Shows the current size of the anonymity set so the user can make an
 * informed privacy decision.
 *
 * - `deposits`: total leaves in the main Merkle tree (every drop ever made)
 * - `poolNotes`: total leaves in the note pool tree (every pool credit ever issued)
 *
 * Anonymity scales with these counts. Honest framing: "your privacy depends
 * on this set being non-trivial." Same approach Privacy Cash uses on their UI.
 *
 * No claim of amount privacy. Just a graph-mixing indicator.
 */
export default function AnonymitySetIndicator() {
  const { connection } = useConnection();
  const [stats, setStats] = useState<PoolStats | null>(null);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [vault] = getVaultPDA();
        const [merkleTree] = getMerkleTreePDA(vault);
        const [notePoolTree] = getNotePoolTreePDA(vault);

        const [merkleInfo, poolInfo] = await Promise.all([
          connection.getAccountInfo(merkleTree),
          connection.getAccountInfo(notePoolTree),
        ]);

        const deposits = merkleInfo ? readTreeNextIndex(merkleInfo.data) : 0;
        const poolNotes = poolInfo ? readTreeNextIndex(poolInfo.data) : 0;
        if (!cancelled) setStats({ deposits, poolNotes });
      } catch (e: any) {
        if (!cancelled) setError(e.message ?? "Failed to load pool stats");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [connection]);

  if (error) {
    return (
      <div className="border border-[rgba(224,224,224,0.1)] bg-[rgba(0,0,0,0.2)] px-4 py-2">
        <p className="font-mono text-[9px] tracking-[0.12em] text-[rgba(224,224,224,0.3)]">
          ANONYMITY SET — UNAVAILABLE
        </p>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="border border-[rgba(224,224,224,0.1)] bg-[rgba(0,0,0,0.2)] px-4 py-2">
        <p className="font-mono text-[9px] tracking-[0.12em] text-[rgba(224,224,224,0.3)]">
          ANONYMITY SET — LOADING…
        </p>
      </div>
    );
  }

  // Strength heuristic — Tornado-style: under 10 is weak, 10-99 is moderate,
  // 100+ is reasonable. These are pool-graph anonymity, not amount privacy.
  const total = stats.deposits + stats.poolNotes;
  let strengthLabel: string;
  let strengthClass: string;
  if (total < 10) {
    strengthLabel = "WEAK — small set";
    strengthClass = "text-[rgba(255,200,0,0.7)]";
  } else if (total < 100) {
    strengthLabel = "MODERATE";
    strengthClass = "text-[rgba(0,255,65,0.55)]";
  } else {
    strengthLabel = "REASONABLE";
    strengthClass = "text-[rgba(0,255,65,0.7)]";
  }

  return (
    <div className="border border-[rgba(0,255,65,0.15)] bg-[rgba(0,255,65,0.02)] px-4 py-2.5">
      <div className="flex items-center justify-between">
        <p className="font-mono text-[9px] tracking-[0.18em] text-[rgba(224,224,224,0.4)]">
          ANONYMITY SET
        </p>
        <p className={`font-mono text-[9px] tracking-[0.14em] ${strengthClass}`}>
          {strengthLabel}
        </p>
      </div>
      <p className="mt-1 font-mono text-[10px] text-[rgba(224,224,224,0.7)]">
        {stats.deposits} deposit{stats.deposits === 1 ? "" : "s"} · {stats.poolNotes} pool note{stats.poolNotes === 1 ? "" : "s"}
      </p>
      <p className="mt-1 text-[9px] leading-relaxed text-[rgba(224,224,224,0.3)]">
        Sender↔recipient unlinkability scales with this count. Boundary amounts remain visible — Solana platform constraint.
      </p>
    </div>
  );
}
