"use client";

import { useState, useEffect } from "react";

interface ProofProgressProps {
  stage: "idle" | "decoding" | "merkle" | "proving" | "submitting" | "done" | "error";
  error?: string;
}

const STAGES = [
  { key: "decoding", label: "Decoding claim code" },
  { key: "merkle", label: "Fetching Merkle proof" },
  { key: "proving", label: "Generating ZK proof" },
  { key: "submitting", label: "Submitting transactions" },
  { key: "done", label: "Claimed" },
];

export default function ProofProgress({ stage, error }: ProofProgressProps) {
  const [dots, setDots] = useState("");

  useEffect(() => {
    if (stage === "idle" || stage === "done" || stage === "error") return;
    const interval = setInterval(() => {
      setDots((d) => (d.length >= 3 ? "" : d + "."));
    }, 400);
    return () => clearInterval(interval);
  }, [stage]);

  if (stage === "idle") return null;

  return (
    <div className="border border-[rgba(0,255,65,0.2)] bg-[#050505] p-6 space-y-3">
      <p className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.2)] mb-4">PROOF PIPELINE</p>
      {STAGES.map(({ key, label }) => {
        const isActive = stage === key;
        const isPast = STAGES.findIndex((s) => s.key === stage) > STAGES.findIndex((s) => s.key === key);
        const isDone = stage === "done";

        return (
          <div key={key} className="flex items-center gap-3 text-sm">
            <span className={isDone || isPast ? "text-[var(--accent)]" : isActive ? "text-[var(--accent)] animate-pulse" : "text-[rgba(224,224,224,0.2)]"}>
              {isDone || isPast ? "[+]" : isActive ? "[>]" : "[ ]"}
            </span>
            <span className={isDone || isPast ? "text-[var(--text)]" : isActive ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.3)]"}>
              {label}{isActive ? dots : ""}
            </span>
          </div>
        );
      })}
      {stage === "error" && error && (
        <div className="mt-4 border border-[rgba(255,0,68,0.2)] bg-[rgba(255,0,68,0.04)] px-5 py-3">
          <p className="text-xs text-[var(--danger)]">{error}</p>
        </div>
      )}
    </div>
  );
}
