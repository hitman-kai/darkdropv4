import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "DarkDrop - Docs",
  description: "Documentation for DarkDrop — unlinkable SOL transfers on Solana using zero-knowledge proofs.",
};

function Section({ id, label, title, children }: { id: string; label: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="arcade-panel">
      <div className="arcade-panel-header">
        <span className="arcade-dot" />
        <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(0,255,65,0.6)]">{label}</span>
      </div>
      <div className="arcade-panel-body space-y-4">
        <h2 className="font-mono text-[clamp(16px,3vw,22px)] font-semibold tracking-[0.06em] text-[var(--text)]">{title}</h2>
        {children}
      </div>
    </section>
  );
}

function P({ children }: { children: React.ReactNode }) {
  return <p className="text-xs sm:text-sm leading-relaxed text-[rgba(224,224,224,0.55)]">{children}</p>;
}

function Accent({ children }: { children: React.ReactNode }) {
  return <span className="text-[var(--accent)] font-semibold">{children}</span>;
}

function Step({ n, title, children }: { n: string; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-4">
      <span className="shrink-0 font-mono text-[10px] tracking-[0.15em] text-[var(--accent)] font-bold">{n}</span>
      <div>
        <p className="font-mono text-xs tracking-[0.06em] text-[var(--text)] mb-1 font-semibold">{title}</p>
        <p className="text-xs leading-relaxed text-[rgba(224,224,224,0.45)]">{children}</p>
      </div>
    </div>
  );
}

function FAQ({ q, children }: { q: string; children: React.ReactNode }) {
  return (
    <div className="border-l-2 border-[var(--accent-dim)] pl-4">
      <p className="font-mono text-xs tracking-[0.04em] text-[var(--text)] mb-1 font-semibold">{q}</p>
      <p className="text-xs leading-relaxed text-[rgba(224,224,224,0.45)]">{children}</p>
    </div>
  );
}

export default function DocsPage() {
  return (
    <div className="mx-auto w-full max-w-2xl px-4 sm:px-6 pb-20" style={{ paddingTop: "80px" }}>
      <div className="mb-8">
        <p className="mb-2 font-mono text-[9px] tracking-[0.3em] text-[var(--accent-dim)]">
          OUTPUT // 0X03 &mdash; DOCUMENTATION
        </p>
        <h1 className="font-mono text-[clamp(24px,4vw,36px)] font-light leading-[1.15] text-[var(--text)]">
          How DarkDrop<br />
          <span className="text-[var(--accent)]">works.</span>
        </h1>
      </div>

      {/* Table of contents */}
      <nav className="mb-8 arcade-panel">
        <div className="arcade-panel-header">
          <span className="arcade-dot" />
          <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">CONTENTS</span>
        </div>
        <div className="arcade-panel-body space-y-1">
          {[
            ["what", "What is DarkDrop"],
            ["how", "How it works"],
            ["credit-note", "The Credit Note Model"],
            ["usage", "How to use it"],
            ["privacy", "Privacy model"],
            ["faq", "FAQ"],
          ].map(([id, label]) => (
            <a
              key={id}
              href={`#${id}`}
              className="block font-mono text-[10px] tracking-[0.08em] text-[rgba(224,224,224,0.4)] hover:text-[var(--accent)] transition-colors"
            >
              &gt; {label}
            </a>
          ))}
        </div>
      </nav>

      <div className="space-y-4">
        {/* What is DarkDrop */}
        <Section id="what" label="0X01" title="What is DarkDrop">
          <P>
            DarkDrop is a privacy protocol on Solana that lets you send SOL to anyone without creating an on-chain link
            between the sender and receiver wallets. It uses zero-knowledge proofs (Groth16 on BN254) to verify that a
            claim is legitimate without revealing which deposit it corresponds to. The sender deposits SOL and receives a
            claim code. The recipient uses the claim code to generate a ZK proof in their browser and withdraw the funds
            to any wallet &mdash; with no connection to the original deposit visible on-chain.
          </P>
        </Section>

        {/* How it works */}
        <Section id="how" label="0X02" title="How it works">
          <P>DarkDrop uses a three-step flow: <Accent>Deposit</Accent>, <Accent>Claim</Accent>, and <Accent>Withdraw</Accent>.</P>
          <div className="space-y-3 mt-2">
            <Step n="01" title="Deposit (create_drop)">
              You deposit SOL into a shared Merkle vault. A cryptographic leaf is inserted into a Merkle tree.
              You receive a claim code containing the secret values needed to prove ownership later.
              The deposit amount is visible on-chain (SOL must physically move).
            </Step>
            <Step n="02" title="Claim (claim_credit)">
              The recipient generates a ZK proof in their browser proving they know the secret for a valid leaf,
              without revealing which leaf. The proof is verified on-chain. A credit note PDA is created.
              Zero SOL moves. Zero amounts appear in the transaction. An observer sees only opaque proof bytes.
            </Step>
            <Step n="03" title="Withdraw (withdraw_credit)">
              The recipient opens the commitment, revealing the amount and blinding factor. The program verifies
              the Poseidon hash on-chain and transfers SOL via direct lamport manipulation &mdash; no CPI, no
              inner instructions, no decoded &ldquo;Transfer&rdquo; on any block explorer.
            </Step>
          </div>
        </Section>

        {/* Credit Note Model */}
        <Section id="credit-note" label="0X03" title="The Credit Note Model">
          <P>
            This is what makes DarkDrop different from other mixers. The claim transaction &mdash; the on-chain event
            that connects a deposit to a withdrawal &mdash; contains <Accent>zero amount information</Accent> and{" "}
            <Accent>zero SOL movement</Accent>.
          </P>
          <P>
            Instead of transferring SOL directly during the claim, DarkDrop creates a credit note: a PDA that stores
            a Poseidon commitment (<Accent>Poseidon(amount, blinding_factor)</Accent>). The amount is a private input
            to the ZK circuit &mdash; it never appears in the instruction data, events, or logs.
          </P>
          <P>
            The withdrawal is a separate transaction, potentially from a different wallet at a different time.
            It uses direct lamport manipulation (the program directly modifies account balances) instead of
            calling <Accent>system_program::transfer</Accent>. This means there are no CPI calls, no inner
            instructions, and no decoded &ldquo;Transfer X SOL&rdquo; on Solscan or any explorer.
          </P>
          <P>
            The IDL uses deliberately uninformative field names &mdash; no field is named &ldquo;amount&rdquo;,
            &ldquo;lamports&rdquo;, &ldquo;fee&rdquo;, or &ldquo;balance&rdquo;. Block explorers cannot auto-label
            the values.
          </P>
        </Section>

        {/* How to use it */}
        <Section id="usage" label="0X04" title="How to use it">
          <P>Step-by-step guide to creating and claiming a drop.</P>
          <div className="space-y-3 mt-2">
            <Step n="01" title="Connect your wallet">
              Click the wallet button in the top-right corner. DarkDrop supports Phantom and Solflare on Solana devnet.
              Make sure you have some devnet SOL for gas fees.
            </Step>
            <Step n="02" title="Create a drop">
              Go to the CREATE page. Enter the SOL amount (up to 100 SOL). Optionally set a password for extra
              protection &mdash; the recipient will need it to claim. Choose Direct deposit or Private deposit
              (via relayer, so your wallet never appears in the DarkDrop transaction). Click CREATE DROP and approve
              the transaction.
            </Step>
            <Step n="03" title="Save and share the claim code">
              After the deposit confirms, you will see a claim code starting with &ldquo;darkdrop:v4:...&rdquo;.
              Copy it and share it with the recipient through any channel (DM, email, QR code, paper).
              Anyone with the code can claim the funds, so keep it secure.
            </Step>
            <Step n="04" title="Claim the drop">
              Go to the CLAIM page. Paste the claim code. If it was password-protected, enter the password.
              Choose Gasless (relayer pays gas, 0.5% fee) or Direct (you pay gas, no fee).
              Click CLAIM. Your browser generates a ZK proof (takes 2-5 seconds), then two transactions are
              submitted: one to verify the proof and create a credit note, one to withdraw the SOL to your wallet.
            </Step>
            <Step n="05" title="Verify on-chain">
              After claiming, check the transaction links on Solscan. You will see that the claim transaction
              has zero decoded amounts and zero SOL transfers. The withdrawal shows balance changes but no
              Transfer instruction.
            </Step>
          </div>
        </Section>

        {/* Privacy model */}
        <Section id="privacy" label="0X05" title="Privacy model">
          <P>DarkDrop is honest about what is hidden and what is not.</P>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-xs border-2 border-[var(--border-dim)]">
              <thead>
                <tr className="border-b-2 border-[var(--border-dim)] bg-[rgba(0,255,65,0.02)]">
                  <th className="py-2.5 px-3 text-left font-mono text-[9px] tracking-[0.15em] text-[rgba(224,224,224,0.3)] font-semibold">DATA POINT</th>
                  <th className="py-2.5 px-3 text-left font-mono text-[9px] tracking-[0.15em] text-[rgba(224,224,224,0.3)] font-semibold">DEPOSIT</th>
                  <th className="py-2.5 px-3 text-left font-mono text-[9px] tracking-[0.15em] text-[rgba(224,224,224,0.3)] font-semibold">CLAIM</th>
                  <th className="py-2.5 px-3 text-left font-mono text-[9px] tracking-[0.15em] text-[rgba(224,224,224,0.3)] font-semibold">WITHDRAW</th>
                </tr>
              </thead>
              <tbody className="text-[rgba(224,224,224,0.5)]">
                <tr className="border-b border-[var(--border-dim)]">
                  <td className="py-2 px-3">Sender wallet</td>
                  <td className="py-2 px-3">Visible</td>
                  <td className="py-2 px-3">Not present</td>
                  <td className="py-2 px-3">Not present</td>
                </tr>
                <tr className="border-b border-[var(--border-dim)]">
                  <td className="py-2 px-3">Receiver wallet</td>
                  <td className="py-2 px-3">Not present</td>
                  <td className="py-2 px-3">Present</td>
                  <td className="py-2 px-3">Present</td>
                </tr>
                <tr className="border-b border-[var(--border-dim)]">
                  <td className="py-2 px-3">Amount</td>
                  <td className="py-2 px-3">Visible (CPI)</td>
                  <td className="py-2 px-3 text-[var(--accent)] font-semibold">Hidden</td>
                  <td className="py-2 px-3">Balance delta only</td>
                </tr>
                <tr className="border-b border-[var(--border-dim)]">
                  <td className="py-2 px-3">Deposit &rarr; Claim link</td>
                  <td className="py-2 px-3 text-[var(--accent)] font-semibold" colSpan={3}>Impossible (Merkle proof hides which leaf)</td>
                </tr>
                <tr>
                  <td className="py-2 px-3">Inner instructions</td>
                  <td className="py-2 px-3">Transfer</td>
                  <td className="py-2 px-3">CreateAccount (PDAs)</td>
                  <td className="py-2 px-3 text-[var(--accent)] font-semibold">None</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div className="mt-4 space-y-2">
            <P>
              <Accent>What&apos;s visible:</Accent> The deposit amount is visible because SOL must physically move.
              The receiver wallet appears in the claim and withdraw transactions. An observer can see that someone
              claimed from the DarkDrop vault.
            </P>
            <P>
              <Accent>What&apos;s hidden:</Accent> The link between sender and receiver. The claim amount.
              Which deposit corresponds to which claim. The withdrawal uses no Transfer instruction, so explorers
              cannot auto-label it.
            </P>
            <P>
              <Accent>Anonymity set:</Accent> Privacy improves with more deposits in the vault. On devnet,
              the anonymity set is small. On mainnet, it would grow with real usage. Using the relayer for
              both deposit and claim provides maximum unlinkability.
            </P>
          </div>
        </Section>

        {/* FAQ */}
        <Section id="faq" label="0X06" title="FAQ">
          <div className="space-y-4">
            <FAQ q="What if the relayer is down?">
              You can always claim directly by selecting &ldquo;Direct&rdquo; mode on the claim page. You will
              pay gas yourself, but the ZK proof and on-chain verification work the same way. The relayer is a
              convenience feature for gasless claims, not a requirement. The create page also supports direct
              deposits that bypass the relayer entirely.
            </FAQ>
            <FAQ q="What if I lose my claim code?">
              The claim code contains the cryptographic secrets needed to generate the ZK proof. Without it,
              there is no way to claim the funds. DarkDrop does not store claim codes anywhere. Treat it like
              a private key &mdash; if you lose it, the SOL remains locked in the vault permanently.
            </FAQ>
            <FAQ q="Is DarkDrop audited?">
              Four audit reports have been published covering the Solana program, ZK circuits, fee and treasury
              logic, and the revoke / note-pool layer. Reports and the fix tracker are in the{" "}
              <a
                href="https://github.com/hitman-kai/darkdropv4/tree/main/audits"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[var(--accent)] hover:underline"
              >
                /audits
              </a>{" "}
              folder on GitHub. DarkDrop remains deployed on Solana devnet only &mdash; we have not yet
              commissioned a third-party firm review, and the code should not be used with real funds on
              mainnet until that step is completed.
            </FAQ>
            <FAQ q="What are the fees?">
              Direct claims have no protocol fee &mdash; you only pay Solana gas (~0.000005 SOL).
              Gasless claims via the relayer have a 0.5% fee deducted from the withdrawal amount.
              The relayer pays all gas costs.
            </FAQ>
            <FAQ q="Can the relayer steal my funds?">
              No. The ZK proof binds the claim to a specific recipient wallet. The relayer submits
              the transaction but cannot change the recipient. It can only refuse to relay (censorship),
              which is mitigated by the direct claim fallback.
            </FAQ>
            <FAQ q="What Solana network does DarkDrop use?">
              DarkDrop is currently deployed on Solana devnet. You need devnet SOL to interact with it.
              Use a faucet or the Solana CLI to get devnet SOL.
            </FAQ>
          </div>
        </Section>
      </div>
    </div>
  );
}
