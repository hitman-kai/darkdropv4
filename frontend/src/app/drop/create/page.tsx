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
import AnonymitySetIndicator from "@/components/AnonymitySetIndicator";
import { snapshotTreeAccount } from "@/lib/merkle";
import { RELAYER_URL, checkRelayerHealth } from "@/lib/relayer";
import { sendWithRetry } from "@/lib/send-with-retry";
import {
  getReceiptPDA,
  saveReceipt,
  bytesToHex,
  bigintToHex32,
} from "@/lib/receipt";
import {
  getNotePoolPDA,
  getNotePoolTreePDA,
} from "@/lib/note-pool";
import { randomFieldElement, bigintToBytes32BE } from "@/lib/crypto";

type Stage = "input" | "confirming" | "done" | "error";
type DepositMode = "direct" | "private" | "pool";

// sha256("global:create_drop")[0..8]
const CREATE_DROP_DISCRIMINATOR = new Uint8Array([157, 142, 145, 247, 92, 73, 59, 48]);

const MIN_SOL = 0.00001; // 10,000 lamports

export default function CreateDropPage() {
  const { publicKey, sendTransaction } = useWallet();
  const { connection } = useConnection();

  const [amount, setAmount] = useState("");
  const [password, setPassword] = useState("");
  const [recipientHint, setRecipientHint] = useState("");
  const [depositMode, setDepositMode] = useState<DepositMode>("direct");
  const [enableRevoke, setEnableRevoke] = useState(false);
  const [stage, setStage] = useState<Stage>("input");
  const [claimCode, setClaimCode] = useState("");
  const [shareLink, setShareLink] = useState("");
  const [error, setError] = useState("");
  const [txSig, setTxSig] = useState("");
  const [receiptSaved, setReceiptSaved] = useState(false);
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

    if (enableRevoke && depositMode !== "direct") {
      setError("Revoke option requires direct deposit (your wallet must sign as depositor).");
      return;
    }
    if (depositMode === "pool" && !relayerOnline) {
      setError("Max privacy mode requires the relayer to be online.");
      return;
    }

    setStage("confirming");
    setError("");
    setReceiptSaved(false);

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

      // Pool mode uses its own preimage — pool_secret, pool_nullifier, pool_blinding.
      // The pool leaf itself is constructed on-chain using the verified amount.
      const poolSecret = randomFieldElement();
      const poolNullifier = randomFieldElement();
      const poolBlinding = randomFieldElement();

      // PDAs
      const [vault] = getVaultPDA();
      const [merkleTree] = getMerkleTreePDA(vault);
      const [treasury] = getTreasuryPDA();
      const [notePoolTree] = getNotePoolTreePDA(vault);

      let sig: string;

      if (depositMode === "pool") {
        // Max privacy: relayer calls create_drop_to_pool. User's wallet only
        // appears as the source of a plain system transfer; the pool entry
        // and the eventual pool claim are unlinkable to them.
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

        const poolParams = new Uint8Array(96);
        poolParams.set(bigintToBytes32BE(poolSecret), 0);
        poolParams.set(bigintToBytes32BE(poolNullifier), 32);
        poolParams.set(bigintToBytes32BE(poolBlinding), 64);

        const resp = await fetch(`${RELAYER_URL}/api/relay/create-drop-to-pool`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            amount: lamports.toString(),
            poolParams: Array.from(poolParams),
            depositTx: depositSig,
          }),
        });
        const result = await resp.json();
        if (!resp.ok) throw new Error(result.error || "Pool deposit relay failed");
        sig = result.signature;
      } else if (depositMode === "private") {
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

        const keys = [
          { pubkey: vault, isSigner: false, isWritable: true },
          { pubkey: merkleTree, isSigner: false, isWritable: true },
          { pubkey: treasury, isSigner: false, isWritable: true },
          { pubkey: publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ];

        if (enableRevoke) {
          // 7-account path: append depositor + deposit_receipt PDA.
          // Depositor == connected wallet (I-02: never let another signer be depositor).
          const [receiptPda] = getReceiptPDA(dropResult.leaf);
          keys.push(
            { pubkey: publicKey, isSigner: true, isWritable: true },
            { pubkey: receiptPda, isSigner: false, isWritable: true },
          );
        }

        const createDropIx = new TransactionInstruction({
          programId: PROGRAM_ID,
          keys,
          data: Buffer.from(ixData),
        });

        const tx = new Transaction().add(createDropIx);
        sig = await sendWithRetry({
          wallet: { sendTransaction },
          connection,
          transaction: tx,
        });
      }

      // Read leaf index + snapshot the appropriate tree (main vs note pool
      // depending on mode). Same on-chain struct layout, different PDA.
      const treePdaForMode = depositMode === "pool" ? notePoolTree : merkleTree;
      const treeAccount = await connection.getAccountInfo(treePdaForMode);
      if (!treeAccount) throw new Error("Failed to read tree account");

      const nextIndex = new DataView(
        treeAccount.data.buffer,
        treeAccount.data.byteOffset
      ).getUint32(8 + 32, true);
      const leafIndex = nextIndex - 1;
      const pathSnapshot = snapshotTreeAccount(treeAccount.data);

      // Encode claim code. For pool flavor, the (secret, nullifier, blinding)
      // fields carry pool_secret / pool_nullifier / pool_blinding — the
      // same semantic slot, reused for the pool leaf preimage.
      const claimPayloadForMode =
        depositMode === "pool"
          ? {
              secret: poolSecret,
              nullifier: poolNullifier,
              amount: lamports,
              blindingFactor: poolBlinding,
            }
          : dropResult.claimPayload;

      const code = await encodeClaimCode(
        {
          ...claimPayloadForMode,
          leafIndex,
          vaultAddress: vault.toBase58(),
          pathSnapshot,
          flavor: depositMode === "pool" ? "pool" : "standard",
        },
        "devnet",
        "sol",
        password || undefined
      );

      if (enableRevoke) {
        saveReceipt({
          leafHex: bytesToHex(dropResult.leaf),
          leafIndex,
          amountLamports: lamports.toString(),
          depositor: publicKey.toBase58(),
          createdAt: Math.floor(Date.now() / 1000),
          cluster: "devnet",
          vaultAddress: vault.toBase58(),
          secretHex: bigintToHex32(dropResult.claimPayload.secret),
          nullifierHex: bigintToHex32(dropResult.claimPayload.nullifier),
          blindingHex: bigintToHex32(dropResult.claimPayload.blindingFactor),
          txSig: sig,
        });
        setReceiptSaved(true);
      }

      setClaimCode(code);
      // Build a shareable URL the recipient can click to auto-fill the claim
      // form. The link encodes the same claim code that's displayed below — no
      // extra privacy property, just a UX upgrade. When a recipient hint was
      // provided we include it so the recipient page can flag a wallet mismatch.
      if (typeof window !== "undefined") {
        const params = new URLSearchParams({ code });
        if (recipientHint.trim()) params.set("for", recipientHint.trim());
        setShareLink(`${window.location.origin}/drop/claim?${params.toString()}`);
      }
      setTxSig(sig);
      setStage("done");
    } catch (err: any) {
      console.error("Create drop failed:", err.message);
      setError(err.message || "Transaction failed");
      setStage("error");
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
            <AnonymitySetIndicator />
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

                {/* Recipient hint (paste-wallet UX) */}
                <div className="arcade-panel">
                  <div className="arcade-panel-header">
                    <span className="arcade-dot" />
                    <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">RECIPIENT WALLET (OPTIONAL)</span>
                  </div>
                  <div className="arcade-panel-body">
                    <input
                      type="text"
                      value={recipientHint}
                      onChange={(e) => setRecipientHint(e.target.value)}
                      placeholder="Paste recipient's wallet address — produces a shareable claim link"
                      className="w-full text-xs font-mono"
                    />
                    <p className="mt-2 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                      Optional. The drop is still bearer (anyone with the link can claim). If filled, you'll get a shareable URL with the wallet hint baked in. Privacy is identical to sharing the raw claim code.
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
                      onClick={() => relayerOnline && !enableRevoke && setDepositMode("private")}
                      disabled={!relayerOnline || enableRevoke}
                      className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                        depositMode === "private"
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      } ${(!relayerOnline || enableRevoke) ? "opacity-40 !cursor-not-allowed" : ""}`}
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
                    <button
                      type="button"
                      onClick={() => relayerOnline && !enableRevoke && setDepositMode("pool")}
                      disabled={!relayerOnline || enableRevoke}
                      className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                        depositMode === "pool"
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      } ${(!relayerOnline || enableRevoke) ? "opacity-40 !cursor-not-allowed" : ""}`}
                    >
                      <span className={`mt-0.5 flex h-4 w-4 items-center justify-center border-2 ${
                        depositMode === "pool"
                          ? "border-[var(--accent)]"
                          : "border-[rgba(224,224,224,0.2)]"
                      }`}>
                        {depositMode === "pool" && <span className="block h-2 w-2 bg-[var(--accent)]" />}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono text-[10px] tracking-[0.12em] font-semibold ${
                            depositMode === "pool" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                          }`}>MAX PRIVACY</span>
                          <span className="arcade-badge">POOL</span>
                        </div>
                        <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                          SOL enters the note pool directly. Second ZK layer hides the leaf → recipient link on top of the relayer hiding your wallet. No revoke option.
                        </p>
                      </div>
                    </button>
                  </div>
                </div>

                {depositMode === "pool" && (
                  <div className="border-2 border-[rgba(255,200,0,0.3)] bg-[rgba(255,200,0,0.04)] px-4 py-3">
                    <p className="font-mono text-[10px] leading-relaxed text-[rgba(255,200,0,0.85)]">
                      <span className="font-semibold tracking-[0.12em]">NO REVOKE PATH.</span>{" "}
                      <span className="text-[rgba(255,200,0,0.7)]">Pool deposits cannot be reclaimed. Lose the claim code and the SOL is permanently locked — no time-lock fallback. Only DIRECT deposits with the revoke option enabled below can be reclaimed after 30 days.</span>
                    </p>
                  </div>
                )}

                {/* Enable revoke */}
                <div className="arcade-panel">
                  <div className="arcade-panel-header">
                    <span className="arcade-dot" />
                    <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">REVOKE OPTION</span>
                  </div>
                  <div className="arcade-panel-body">
                    <button
                      type="button"
                      onClick={() => {
                        const next = !enableRevoke;
                        setEnableRevoke(next);
                        if (next) setDepositMode("direct");
                      }}
                      className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                        enableRevoke
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      }`}
                    >
                      <span className={`mt-0.5 flex h-4 w-4 items-center justify-center border-2 ${
                        enableRevoke
                          ? "border-[var(--accent)]"
                          : "border-[rgba(224,224,224,0.2)]"
                      }`}>
                        {enableRevoke && <span className="block h-2 w-2 bg-[var(--accent)]" />}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono text-[10px] tracking-[0.12em] font-semibold ${
                            enableRevoke ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                          }`}>ENABLE REVOKE (30-DAY LOCK)</span>
                        </div>
                        <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                          Reclaim unclaimed drops after a 30-day time-lock. DIRECT-only — PRIVATE and MAX PRIVACY are disabled here because a receipt needs the depositor as on-chain signer, which is incompatible with relayer-only submission. Privacy cost: links your wallet to (leaf, amount) on-chain.
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
                  {depositMode === "pool" ? "MAX PRIVACY DEPOSIT" : depositMode === "private" ? "PRIVATE DEPOSIT" : enableRevoke ? "CREATE DROP + RECEIPT" : "CREATE DROP"}
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

            {shareLink && (
              <div className="arcade-panel">
                <div className="arcade-panel-header">
                  <span className="arcade-dot" />
                  <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">SHAREABLE LINK</span>
                </div>
                <div className="arcade-panel-body space-y-2">
                  <p className="break-all font-mono text-[10px] leading-relaxed text-[rgba(0,255,65,0.5)]">
                    {shareLink}
                  </p>
                  <button
                    onClick={() => {
                      void navigator.clipboard.writeText(shareLink);
                    }}
                    className="arcade-btn-ghost px-4 py-2 font-mono text-[9px] tracking-[0.15em]"
                  >
                    COPY LINK
                  </button>
                  <p className="text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                    Send this link to the recipient instead of the raw claim code. Clicking it pre-fills the claim form.
                  </p>
                </div>
              </div>
            )}

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

            {receiptSaved && (
              <div className="border-2 border-[rgba(0,255,65,0.2)] bg-[rgba(0,255,65,0.03)] px-5 py-3">
                <p className="text-[10px] leading-relaxed text-[rgba(224,224,224,0.55)]">
                  Revoke receipt saved to this browser. If the drop is not claimed, you can reclaim it after 30 days from <a href="/drop/manage" className="text-[var(--accent)] hover:underline">/drop/manage</a>. The preimage lives only in this browser — back it up if you switch devices.
                </p>
              </div>
            )}

            <button
              onClick={() => {
                setStage("input");
                setAmount("");
                setPassword("");
                setRecipientHint("");
                setClaimCode("");
                setShareLink("");
                setReceiptSaved(false);
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
