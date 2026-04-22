import Link from "next/link";

export default function Footer() {
  return (
    <footer className="relative z-10 border-t-2 border-[var(--border)] px-6 sm:px-10 py-5 bg-[rgba(0,0,0,0.8)]">
      <div className="mx-auto flex max-w-4xl flex-col sm:flex-row items-center gap-4 sm:gap-5">
        {/* Nav links */}
        <div className="flex items-center gap-4">
          <Link
            href="/docs"
            className="font-mono text-[9px] tracking-[0.18em] text-[rgba(224,224,224,0.35)] hover:text-[var(--accent)] transition-colors"
          >
            DOCS
          </Link>
          <a
            href="https://x.com/darkdrop_sol"
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-[9px] tracking-[0.18em] text-[rgba(224,224,224,0.35)] hover:text-[var(--accent)] transition-colors"
          >
            TWITTER
          </a>
          <a
            href="https://github.com/hitman-kai/darkdropv4"
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-[9px] tracking-[0.18em] text-[rgba(224,224,224,0.35)] hover:text-[var(--accent)] transition-colors"
          >
            GITHUB
          </a>
        </div>

        {/* Separator */}
        <div className="hidden sm:block h-3 w-px bg-[var(--border)]" />

        {/* Program info */}
        <div className="flex items-center gap-3">
          <span className="font-mono text-[9px] tracking-[0.2em] text-[rgba(224,224,224,0.2)]">PROGRAM</span>
          <span className="font-mono text-[11px] tracking-[0.04em] text-[rgba(224,224,224,0.35)]">
            GSig1QYV...AgkU
          </span>
        </div>

        {/* Badges */}
        <div className="flex items-center gap-2 sm:ml-auto">
          <span className="arcade-badge">V4 DEVNET</span>
          <a
            href="https://github.com/hitman-kai/darkdropv4/tree/main/audits"
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-[9px] tracking-[0.12em] text-[rgba(224,224,224,0.35)] hover:text-[var(--accent)] transition-colors"
          >
            4 AUDITS
          </a>
        </div>
      </div>
    </footer>
  );
}
