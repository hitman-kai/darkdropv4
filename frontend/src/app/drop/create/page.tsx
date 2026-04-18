"use client";

import { useState, useEffect } from "react";
import { useWallet, useConnection } from "@solana/wallet-adapter-react";
import {
  Transaction,
  TransactionInstruction,
  SystemProgram,
} from "@solana/web3.js";
import CodeDisplay from "@/components/CodeDisplay";

import { initPoseidon } from "@/lib/crypto";
import {
  prepareCreateDrop,
  getVaultPDA,
  getMerkleTreePDA,
  getTreasuryPDA,
  PROGRAM_ID,
} from "@/lib/vault";
import { encodeClaimCode } from "@/lib/claim-code";
import { RELAYER_URL, checkRelayerHealth } from "@/lib/relayer";

type Stage = "input" | "confirming" | "done" | "error";
type DepositMode = "direct" | "private";

// sha256("global:create_drop")[0..8]
const CREATE_DROP_DISCRIMINATOR = new Uint8Array([157, 142, 145, 247, 92, 73, 59, 48]);

const MIN_SOL = 0.00001; // 10,000 lamports

export default function CreateDropPage() {
  const { publicKey, sendTransaction } = useWallet();
  const { connection } = useConnection();

  const [amount, setAmount] = useState("");
  const [password, setPassword] = useState("");
  const [depositMode, setDepositMode] = useState<DepositMode>("direct");
  const [stage, setStage] = useState<Stage>("input");
  const [claimCode, setClaimCode] = useState("");
  const [error, setError] = useState("");
  const [txSig, setTxSig] = useState("");
  const [relayerOnline, setRelayerOnline] = useState<boolean | null>(null);

  useEffect(() => {
    checkRelayerHealth().then((online) => {
      setRelayerOnline(online);
      setDepositMode(online ? "private" : "direct");
    });
  }, []);

  const handleCreateDrop = async () => {
    if (!publicKey || !sendTransaction) return;

    const solAmount = parseFloat(amount);
    if (isNaN(solAmount) || solAmount <= 0) {
      setError("Enter a valid SOL amount");
      return;
    }
    if (solAmount < MIN_SOL) {
      setError(`Minimum deposit: ${MIN_SOL} SOL`);
      return;
    }
    if (solAmount > 100) {
      setError("Drop cap: 100 SOL maximum");
      return;
    }

    setStage("confirming");
    setError("");
    window.dispatchEvent(new CustomEvent('darkdrop-processing-create', { detail: { active: true } }));

    try {
      const lamports = BigInt(Math.round(solAmount * 1e9));

      // Initialize Poseidon hasher
      await initPoseidon();

      // Generate cryptographic values and compute leaf + commitment
      const pwdBigint = password
        ? BigInt(
            "0x" +
              Array.from(new TextEncoder().encode(password))
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("")
          )
        : undefined;

      const dropResult = prepareCreateDrop(lamports, pwdBigint);

      // PDAs
      const [vault] = getVaultPDA();
      const [merkleTree] = getMerkleTreePDA(vault);
      const [treasury] = getTreasuryPDA();

      let sig: string;

      if (depositMode === "private") {
        // Private deposit: send SOL to relayer wallet, relayer calls create_drop
        // Step 1: Transfer SOL to relayer via normal system transfer
        const relayerPubkey = await fetch(`${RELAYER_URL}/health`)
          .then(r => r.json())
          .then(d => d.relayerPubkey);

        if (!relayerPubkey) throw new Error("Relayer not available");

        const { PublicKey: PK } = await import("@solana/web3.js");
        const transferIx = SystemProgram.transfer({
          fromPubkey: publicKey,
          toPubkey: new PK(relayerPubkey),
          lamports: Number(lamports),
        });
        const transferTx = new Transaction().add(transferIx);
        const depositSig = await sendTransaction(transferTx, connection);
        await connection.confirmTransaction(depositSig, "confirmed");

        // Step 2: Tell relayer to call create_drop
        const resp = await fetch(`${RELAYER_URL}/api/relay/create-drop`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            leaf: Array.from(dropResult.leaf),
            amount: lamports.toString(),
            commitment: Array.from(dropResult.amountCommitment),
            seed: Array.from(dropResult.passwordHash),
            depositTx: depositSig,
          }),
        });
        const result = await resp.json();
        if (!resp.ok) throw new Error(result.error || "Deposit relay failed");
        sig = result.signature;
      } else {
        // Direct deposit: user calls create_drop directly
        const amountBuf = new Uint8Array(8);
        new DataView(amountBuf.buffer).setBigUint64(0, lamports, true);

        const ixData = new Uint8Array(8 + 32 + 8 + 32 + 32);
        let offset = 0;
        ixData.set(CREATE_DROP_DISCRIMINATOR, offset); offset += 8;
        ixData.set(dropResult.leaf, offset); offset += 32;
        ixData.set(amountBuf, offset); offset += 8;
        ixData.set(dropResult.amountCommitment, offset); offset += 32;
        ixData.set(dropResult.passwordHash, offset);

        const createDropIx = new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: vault, isSigner: false, isWritable: true },
            { pubkey: merkleTree, isSigner: false, isWritable: true },
            { pubkey: treasury, isSigner: false, isWritable: true },
            { pubkey: publicKey, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
          data: Buffer.from(ixData),
        });

        const tx = new Transaction().add(createDropIx);
        sig = await sendTransaction(tx, connection);
        await connection.confirmTransaction(sig, "confirmed");
      }

      // Read the leaf index from the on-chain Merkle tree
      const treeAccount = await connection.getAccountInfo(merkleTree);
      if (!treeAccount) throw new Error("Failed to read Merkle tree account");

      // Layout: discriminator(8) + vault(32) + next_index(u32 LE at offset 40)
      const nextIndex = new DataView(
        treeAccount.data.buffer,
        treeAccount.data.byteOffset
      ).getUint32(8 + 32, true);
      const leafIndex = nextIndex - 1;

      // Encode claim code
      const code = await encodeClaimCode(
        {
          ...dropResult.claimPayload,
          leafIndex,
          vaultAddress: vault.toBase58(),
        },
        "devnet",
        "sol",
        password || undefined
      );

      setClaimCode(code);
      setTxSig(sig);
      setStage("done");
      window.dispatchEvent(new CustomEvent('darkdrop-processing-create', { detail: { active: false } }));
    } catch (err: any) {
      console.error("Create drop failed:", err.message);
      setError(err.message || "Transaction failed");
      setStage("error");
      window.dispatchEvent(new CustomEvent('darkdrop-processing-create', { detail: { active: false } }));
    }
  };

  return (
    <div className="mx-auto w-full max-w-xl px-4 sm:px-6 pb-20" style={{ paddingTop: "80px" }}>
      <div className="mb-8">
        <p className="mb-2 font-mono text-[9px] tracking-[0.3em] text-[var(--accent-dim)]">
          OUTPUT // 0X01
        </p>
        <h1 className="font-mono text-[clamp(24px,4vw,36px)] font-light leading-[1.15] text-[var(--text)]">
          Create a<br />dead drop.
        </h1>
        <p className="mt-3 text-xs leading-relaxed text-[rgba(224,224,224,0.45)]">
          Deposit SOL into the Merkle vault. You will receive a claim code to share with anyone.
        </p>
      </div>

        {(stage === "input" || stage === "error") ? (
          <div className="space-y-4">
            {!publicKey && (
              <div className="arcade-panel">
                <div className="arcade-panel-body text-center text-sm text-[rgba(224,224,224,0.4)]">
                  Connect your wallet to create a drop.
                </div>
              </div>
            )}

            {publicKey && (
              <>
                {/* Amount field */}
                <div className="arcade-panel">
                  <div className="arcade-panel-header">
                    <span className="arcade-dot" />
                    <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">AMOUNT (SOL)</span>
                  </div>
                  <div className="arcade-panel-body">
                    <input
                      type="number"
                      step="0.001"
                      min={MIN_SOL}
                      max="100"
                      value={amount}
                      onChange={(e) => setAmount(e.target.value)}
                      placeholder="0.00"
                      className="w-full text-[var(--accent)] text-lg font-mono"
                    />
                  </div>
                </div>

                {/* Password field */}
                <div className="arcade-panel">
                  <div className="arcade-panel-header">
                    <span className="arcade-dot" />
                    <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">PASSWORD (OPTIONAL)</span>
                  </div>
                  <div className="arcade-panel-body">
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Leave empty for no password"
                      className="w-full text-sm font-mono"
                    />
                    <p className="mt-2 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                      If set, the recipient must enter this password to claim. Enforced at the protocol level via ZK proof.
                    </p>
                  </div>
                </div>

                {/* Deposit mode */}
                <div className="arcade-panel">
                  <div className="arcade-panel-header justify-between">
                    <div className="flex items-center gap-3">
                      <span className="arcade-dot" />
                      <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">DEPOSIT METHOD</span>
                    </div>
                    {relayerOnline !== null && (
                      <span className={`font-mono text-[8px] tracking-[0.12em] flex items-center gap-1.5 ${relayerOnline ? "text-[rgba(0,255,65,0.5)]" : "text-[rgba(224,224,224,0.25)]"}`}>
                        <span className={relayerOnline ? "arcade-dot" : "arcade-dot arcade-dot-off"} style={{ height: 5, width: 5 }} />
                        {relayerOnline ? "RELAYER: ONLINE" : "RELAYER: OFFLINE"}
                      </span>
                    )}
                  </div>
                  <div className="arcade-panel-body space-y-2">
                    <button
                      type="button"
                      onClick={() => setDepositMode("direct")}
                      className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                        depositMode === "direct"
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      }`}
                    >
                      <span className={`mt-0.5 flex h-4 w-4 items-center justify-center border-2 ${
                        depositMode === "direct"
                          ? "border-[var(--accent)]"
                          : "border-[rgba(224,224,224,0.2)]"
                      }`}>
                        {depositMode === "direct" && <span className="block h-2 w-2 bg-[var(--accent)]" />}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono text-[10px] tracking-[0.12em] font-semibold ${
                            depositMode === "direct" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                          }`}>DIRECT</span>
                        </div>
                        <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                          Your wallet calls the program directly. Deposit amount is visible on-chain.
                        </p>
                      </div>
                    </button>
                    <button
                      type="button"
                      onClick={() => relayerOnline && setDepositMode("private")}
                      disabled={!relayerOnline}
                      className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                        depositMode === "private"
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      } ${!relayerOnline ? "opacity-40 !cursor-not-allowed" : ""}`}
                    >
                      <span className={`mt-0.5 flex h-4 w-4 items-center justify-center border-2 ${
                        depositMode === "private"
                          ? "border-[var(--accent)]"
                          : "border-[rgba(224,224,224,0.2)]"
                      }`}>
                        {depositMode === "private" && <span className="block h-2 w-2 bg-[var(--accent)]" />}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono text-[10px] tracking-[0.12em] font-semibold ${
                            depositMode === "private" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                          }`}>PRIVATE DEPOSIT</span>
                          <span className="arcade-badge">RELAYER</span>
                        </div>
                        <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                          SOL routes through the relayer. Your wallet never appears in the DarkDrop TX.
                        </p>
                      </div>
                    </button>
                  </div>
                </div>

                {error && (
                  <div className="border-2 border-[rgba(255,0,68,0.3)] bg-[rgba(255,0,68,0.04)] px-5 py-3 shadow-[2px_2px_0_rgba(255,0,68,0.2)]">
                    <p className="text-xs text-[var(--danger)] font-semibold">{error}</p>
                  </div>
                )}

                <button
                  onClick={handleCreateDrop}
                  disabled={!amount}
                  className="arcade-btn-primary w-full py-3.5 font-mono text-[10px] tracking-[0.2em]"
                >
                  {depositMode === "private" ? "PRIVATE DEPOSIT" : "CREATE DROP"}
                </button>
              </>
            )}
          </div>
        ) : stage === "confirming" ? (
          <div className="arcade-panel arcade-glow">
            <div className="arcade-panel-body p-8 text-center">
              <div className="text-[var(--accent)] animate-pulse text-sm mb-2 font-semibold">
                Confirming transaction...
              </div>
              <div className="text-[10px] text-[rgba(224,224,224,0.3)]">
                Approve the transaction in your wallet.
              </div>
            </div>
          </div>
        ) : stage === "done" ? (
          <div className="space-y-4">
            <div className="arcade-panel arcade-glow">
              <div className="arcade-panel-header justify-center">
                <span className="arcade-dot" />
                <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(0,255,65,0.6)]">DROP CREATED</span>
              </div>
              <div className="arcade-panel-body text-center">
                <p className="text-sm text-[rgba(224,224,224,0.5)]">{amount} SOL deposited to vault</p>
              </div>
            </div>

            <CodeDisplay code={claimCode} />

            {txSig && (
              <div className="text-center">
                <a
                  href={`https://solscan.io/tx/${txSig}?cluster=devnet`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-[10px] tracking-[0.1em] text-[rgba(0,255,65,0.5)] hover:text-[var(--accent)] transition-colors"
                >
                  VIEW TRANSACTION ON SOLSCAN
                </a>
              </div>
            )}

            <div className="border-2 border-[rgba(255,0,68,0.2)] bg-[rgba(255,0,68,0.02)] px-5 py-3">
              <p className="text-[10px] leading-relaxed text-[rgba(224,224,224,0.4)]">
                Share this code with the recipient. Anyone with the code can claim the funds{password ? " (password required)" : ""}. Store it securely.
              </p>
            </div>

            <button
              onClick={() => {
                setStage("input");
                setAmount("");
                setPassword("");
                setClaimCode("");
              }}
              className="arcade-btn-ghost w-full py-3 font-mono text-[10px] tracking-[0.15em]"
            >
              CREATE ANOTHER
            </button>
          </div>
        ) : null}
    </div>
  );
}
