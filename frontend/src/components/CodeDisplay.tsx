"use client";

import { useState } from "react";

interface CodeDisplayProps {
  code: string;
  label?: string;
}

export default function CodeDisplay({ code, label = "CLAIM CODE" }: CodeDisplayProps) {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="border border-[rgba(0,255,65,0.2)] bg-[#050505]">
      <div className="border-b border-[rgba(0,255,65,0.15)] px-5 py-3 flex items-center gap-3">
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--accent)] shadow-[0_0_6px_var(--accent)]" />
        <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(0,255,65,0.6)]">{label}</span>
      </div>
      <div className="p-5">
        <div className="border border-[rgba(0,255,65,0.15)] bg-[#020202] p-4 cursor-pointer hover:border-[rgba(0,255,65,0.3)] transition-colors" onClick={copyToClipboard} title="Click to copy">
          <p className="break-all font-mono text-[11px] leading-relaxed text-[var(--accent)]">{code}</p>
        </div>
        <div className="mt-3 flex gap-2">
          <button
            type="button"
            onClick={copyToClipboard}
            className="flex-1 border-[rgba(0,255,65,0.3)] py-2.5 font-mono text-[9px] tracking-[0.15em] text-[var(--accent)]"
          >
            {copied ? "COPIED" : "COPY CODE"}
          </button>
        </div>
      </div>
    </div>
  );
}
