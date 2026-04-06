"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import dynamic from "next/dynamic";

const WalletMultiButton = dynamic(
  () => import("@solana/wallet-adapter-react-ui").then((mod) => mod.WalletMultiButton),
  { ssr: false }
);

export default function Navbar() {
  const path = usePathname();

  const linkClass = (href: string) =>
    `px-4 py-1.5 font-mono text-[10px] tracking-[0.15em] transition-colors ${
      path === href
        ? "text-[var(--accent)]"
        : "text-[rgba(224,224,224,0.5)] hover:text-[var(--accent)]"
    }`;

  return (
    <nav
      className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between border-b border-[rgba(0,255,65,0.12)] bg-[rgba(0,0,0,0.92)] px-8 backdrop-blur-md"
      style={{ height: "52px" }}
    >
      <Link href="/" className="font-mono text-[13px] tracking-[0.22em] text-[var(--accent)]">
        DARKDROP
      </Link>
      <div className="flex items-center gap-1 border border-[rgba(0,255,65,0.15)] px-1 py-1">
        <Link href="/drop/create" className={linkClass("/drop/create")}>CREATE</Link>
        <Link href="/drop/claim" className={linkClass("/drop/claim")}>CLAIM</Link>
      </div>
      <WalletMultiButton
        style={{
          backgroundColor: "rgba(0, 255, 65, 0.08)",
          border: "1px solid rgba(0, 255, 65, 0.5)",
          color: "var(--accent)",
          fontFamily: "var(--font-fira), monospace",
          fontSize: "0.65rem",
          height: "34px",
          letterSpacing: "0.2em",
          textTransform: "uppercase",
          padding: "0 16px",
        }}
      />
    </nav>
  );
}
