"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import dynamic from "next/dynamic";

const WalletMultiButton = dynamic(
  () => import("@solana/wallet-adapter-react-ui").then((mod) => mod.WalletMultiButton),
  { ssr: false, loading: () => <span className="font-mono text-[9px] text-[var(--accent-dim)]">...</span> }
);

export default function Navbar() {
  const path = usePathname();

  const linkClass = (href: string) =>
    `px-2.5 sm:px-4 py-1.5 font-mono text-[8px] sm:text-[10px] tracking-[0.1em] sm:tracking-[0.15em] transition-all whitespace-nowrap ${
      path === href
        ? "text-[var(--accent)] bg-[rgba(0,255,65,0.08)]"
        : "text-[rgba(224,224,224,0.5)] hover:text-[var(--accent)] hover:bg-[rgba(0,255,65,0.04)]"
    }`;

  return (
    <nav
      className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between gap-2 sm:gap-4 border-b-2 border-[var(--border)] bg-[rgba(0,0,0,0.95)] px-3 sm:px-8"
      style={{ height: "52px" }}
    >
      {/* Logo — left */}
      <div className="flex items-center gap-2 shrink-0">
        <Link href="/" className="font-mono text-[10px] sm:text-[13px] tracking-[0.18em] sm:tracking-[0.22em] text-[var(--accent)] font-bold">
          DARKDROP
        </Link>
        <span className="hidden sm:inline-flex font-mono text-[8px] tracking-[0.25em] text-[var(--accent-dim)] border border-[var(--border)] px-1.5 py-0.5 leading-none">
          DEVNET
        </span>
      </div>

      {/* Nav links — center */}
      <div className="flex items-center gap-0 border-2 border-[var(--border)] bg-[rgba(0,0,0,0.5)] shrink-0">
        <Link href="/drop/create" className={linkClass("/drop/create")}>CREATE</Link>
        <div className="w-px h-5 bg-[var(--border-dim)]" />
        <Link href="/drop/claim" className={linkClass("/drop/claim")}>CLAIM</Link>
        <div className="w-px h-5 bg-[var(--border-dim)]" />
        <Link href="/drop/manage" className={linkClass("/drop/manage")}>MANAGE</Link>
        <div className="w-px h-5 bg-[var(--border-dim)]" />
        <Link href="/docs" className={linkClass("/docs")}>DOCS</Link>
      </div>

      {/* Wallet — right */}
      <div className="shrink-0">
        <WalletMultiButton />
      </div>
    </nav>
  );
}
