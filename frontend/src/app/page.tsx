import Link from "next/link";

export default function Home() {
  return (
    <div className="relative flex min-h-screen flex-col arcade-grid">
      <div className="flex flex-1 flex-col justify-center" style={{ paddingTop: "80px" }}>
        <div className="relative mx-auto w-full max-w-4xl px-5 sm:px-10 py-12 sm:py-20">
          {/* Left accent bar */}
          <div className="absolute left-5 sm:left-10 top-0 bottom-0 w-[2px] bg-gradient-to-b from-transparent via-[var(--accent-dim)] to-transparent" />

          <p className="mb-8 pl-4 sm:pl-6 font-mono text-[9px] sm:text-[10px] tracking-[0.35em] text-[var(--accent-dim)]">
            OUTPUT // 0X00 — UNLINKABLE SOLANA TRANSFERS
          </p>

          <h1 className="mb-6 pl-4 sm:pl-6 font-mono text-[clamp(28px,5vw,64px)] font-light leading-[1.1] tracking-tight text-[var(--text)]">
            Zero-knowledge<br />
            <span className="text-[var(--accent)]">dead drops.</span>
          </h1>

          <p className="mb-10 pl-4 sm:pl-6 max-w-md text-xs sm:text-sm leading-relaxed text-[rgba(224,224,224,0.5)]">
            No decoded amounts in the claim transaction.<br />
            No inner instructions on withdrawal.<br />
            Sender and receiver never linked on-chain.
          </p>

          {/* CTA buttons */}
          <div className="mb-12 flex flex-wrap gap-4 pl-4 sm:pl-6">
            <Link
              href="/drop/create"
              className="arcade-btn-primary inline-block border-2 border-[var(--accent)] bg-[var(--accent)] px-6 sm:px-8 py-3.5 font-mono text-[10px] font-bold tracking-[0.2em] !text-black transition-all hover:bg-[#33ff66] shadow-[3px_3px_0_rgba(0,200,30,0.5)] hover:shadow-[2px_2px_0_rgba(0,200,30,0.4)] hover:translate-x-[1px] hover:translate-y-[1px] active:shadow-none active:translate-x-[3px] active:translate-y-[3px]"
            >
              CREATE DROP
            </Link>
            <Link
              href="/drop/claim"
              className="arcade-btn-ghost inline-block border-2 border-[var(--border)] px-6 sm:px-8 py-3.5 font-mono text-[10px] tracking-[0.2em] text-[rgba(224,224,224,0.6)] transition-all hover:border-[var(--accent-dim)] hover:text-[var(--text)] shadow-[2px_2px_0_rgba(0,255,65,0.15)] hover:shadow-[1px_1px_0_rgba(0,255,65,0.1)] hover:translate-x-[1px] hover:translate-y-[1px]"
            >
              CLAIM DROP
            </Link>
          </div>

          {/* Three-step arcade panels */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 ml-4 sm:ml-6">
            {[
              { step: "01", title: "DEPOSIT", desc: "SOL enters the Merkle vault. You receive a claim code. Share it however you want." },
              { step: "02", title: "CLAIM", desc: "ZK proof verified on-chain. Credit note created. Zero SOL moves. Zero amounts visible." },
              { step: "03", title: "WITHDRAW", desc: "SOL arrives via direct lamport manipulation. No Transfer instruction. No inner CPI. Credit note destroyed." },
            ].map(({ step, title, desc }) => (
              <div
                key={step}
                className="arcade-panel transition-all hover:translate-x-[-1px] hover:translate-y-[-1px] hover:shadow-[4px_4px_0_rgba(0,255,65,0.3)]"
              >
                <div className="arcade-panel-header">
                  <span className="arcade-dot" />
                  <span className="font-mono text-[9px] tracking-[0.3em] text-[rgba(224,224,224,0.25)]">STEP {step}</span>
                </div>
                <div className="arcade-panel-body">
                  <p className="mb-3 font-mono text-[15px] font-semibold tracking-[0.12em] text-[var(--accent)]">{title}</p>
                  <p className="text-xs leading-relaxed text-[rgba(224,224,224,0.5)]">{desc}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Powered By strip */}
          <div className="mt-16 ml-4 sm:ml-6">
            <p className="mb-6 font-mono text-[9px] sm:text-[10px] tracking-[0.35em] text-[var(--accent-dim)]">
              POWERED BY // RPC INFRASTRUCTURE
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 md:gap-10 items-center">
              {[
                { name: "Alchemy", href: "https://alchemy.com", src: "/logos/alchemy.svg" },
                { name: "Chainstack", href: "https://chainstack.com", src: "/logos/chainstack.svg" },
                { name: "Helius", href: "https://helius.dev", src: "/logos/helius.svg" },
                { name: "QuickNode", href: "https://quicknode.com", src: "/logos/quicknode.jpg" },
              ].map(({ name, href, src }) => (
                <a
                  key={name}
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={name}
                  className="logo-hover-dim flex items-center justify-center h-8"
                >
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={src} alt={name} className="max-h-8 max-w-full object-contain" />
                </a>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
