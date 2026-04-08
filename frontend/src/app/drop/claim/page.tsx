"use client";

import { useState, useEffect } from "react";
import { useWallet, useConnection } from "@solana/wallet-adapter-react";
import {
  Transaction,
  TransactionInstruction,
  ComputeBudgetProgram,
  SystemProgram,
  PublicKey,
} from "@solana/web3.js";
import ProofProgress from "@/components/ProofProgress";

import {
  initPoseidon,
  poseidonHash,
  nullifierHash as computeNullifierHash,
  amountCommitment as computeAmountCommitment,
  passwordHash as computePasswordHash,
  bigintToBytes32BE,
  bytes32BEToBigint,
} from "@/lib/crypto";
import { decodeClaimCode } from "@/lib/claim-code";
import { generateClaimProofV2 } from "@/lib/proof";
import {
  PROGRAM_ID,
  getVaultPDA,
  getMerkleTreePDA,
  getTreasuryPDA,
  getNullifierPDA,
  getCreditNotePDA,
} from "@/lib/vault";
import { RELAYER_URL, RELAYER_FEE_BPS, checkRelayerHealth } from "@/lib/relayer";

type Stage =
  | "idle"
  | "decoding"
  | "merkle"
  | "proving"
  | "claiming"
  | "withdrawing"
  | "done"
  | "error";

type ClaimMode = "direct" | "relayer";

const MERKLE_DEPTH = 20;
const CLAIM_CREDIT_DISCRIMINATOR = new Uint8Array([190, 242, 172, 79, 29, 82, 22, 163]);
const WITHDRAW_CREDIT_DISCRIMINATOR = new Uint8Array([8, 173, 134, 129, 40, 255, 134, 30]);

export default function ClaimPage() {
  const { publicKey, sendTransaction } = useWallet();
  const { connection } = useConnection();

  const [claimCode, setClaimCode] = useState("");
  const [password, setPassword] = useState("");
  const [claimMode, setClaimMode] = useState<ClaimMode>("relayer");
  const [stage, setStage] = useState<Stage>("idle");
  const [error, setError] = useState("");
  const [claimTxSig, setClaimTxSig] = useState("");
  const [withdrawTxSig, setWithdrawTxSig] = useState("");
  const [claimedAmount, setClaimedAmount] = useState("");
  const [feeAmount, setFeeAmount] = useState("");
  const [relayerOnline, setRelayerOnline] = useState<boolean | null>(null);

  useEffect(() => {
    checkRelayerHealth().then((online) => {
      setRelayerOnline(online);
      setClaimMode(online ? "relayer" : "direct");
    });
  }, []);

  const handleClaim = async () => {
    if (claimMode === "direct" && (!publicKey || !sendTransaction)) {
      setError("Connect your wallet for direct claims.");
      setStage("error");
      return;
    }
    if (claimMode === "relayer" && !publicKey) {
      setError("Connect your wallet so the relayer knows where to send funds.");
      setStage("error");
      return;
    }

    if (!claimCode.startsWith("darkdrop:v4:")) {
      setError("Invalid claim code — must start with darkdrop:v4:");
      setStage("error");
      return;
    }

    setError("");

    try {
      // Step 1: Decode claim code
      setStage("decoding");
      await initPoseidon();

      const parts = claimCode.split(":");
      const encryption = parts[4];
      if (encryption === "aes" && !password) {
        setError("This drop is password-protected. Enter the password.");
        setStage("error");
        return;
      }

      const decoded = await decodeClaimCode(
        claimCode,
        encryption === "aes" ? password : undefined
      );
      const { secret, nullifier, amount, blindingFactor, leafIndex } =
        decoded.payload;

      const amountSol = Number(amount) / 1e9;

      // Compute derived values
      const nullHash = computeNullifierHash(nullifier);
      const amtCommitment = computeAmountCommitment(amount, blindingFactor);
      const pwdBigint = password
        ? BigInt(
            "0x" +
              Array.from(new TextEncoder().encode(password))
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("")
          )
        : 0n;
      const pwdHash = computePasswordHash(pwdBigint);

      // Step 2: Fetch on-chain Merkle tree and build proof path
      setStage("merkle");

      const [vault] = getVaultPDA();
      const [merkleTree] = getMerkleTreePDA(vault);

      const treeAccount = await connection.getAccountInfo(merkleTree);
      if (!treeAccount) throw new Error("Failed to read Merkle tree account");

      const treeData = treeAccount.data;

      const onChainRoot = treeData.slice(8 + 32 + 4 + 4, 8 + 32 + 4 + 4 + 32);
      const filledSubtreesOffset = 8 + 32 + 4 + 4 + 32 + 30 * 32;

      const zeroHashes = computeZeroHashes();
      const pathElements: bigint[] = [];
      const pathIndices: number[] = [];
      let idx = leafIndex;
      for (let i = 0; i < MERKLE_DEPTH; i++) {
        const bit = idx & 1;
        pathIndices.push(bit);
        if (bit === 0) {
          pathElements.push(zeroHashes[i]);
        } else {
          const subtreeBytes = treeData.slice(
            filledSubtreesOffset + i * 32,
            filledSubtreesOffset + (i + 1) * 32
          );
          pathElements.push(bytes32BEToBigint(subtreeBytes));
        }
        idx = idx >> 1;
      }

      const merkleRootBigInt = bytes32BEToBigint(onChainRoot);

      // Step 3: Generate ZK proof (V2 — amount is PRIVATE)
      setStage("proving");

      const proofResult = await generateClaimProofV2(
        { secret, nullifier, amount, blindingFactor, password: pwdBigint },
        { pathElements, pathIndices, root: merkleRootBigInt },
        publicKey!,
        nullHash,
        amtCommitment,
        pwdHash
      );

      // Step 3: Submit claim_credit
      setStage("claiming");

      const nullifierHashBytes = bigintToBytes32BE(nullHash);
      const [nullifierPDA] = getNullifierPDA(nullifierHashBytes);
      const [creditNotePDA] = getCreditNotePDA(nullifierHashBytes);
      const [treasury] = getTreasuryPDA();

      // Pack opaque inputs: merkle_root(32) + commitment(32) + seed(32)
      const opaqueInputs = new Uint8Array(96);
      opaqueInputs.set(onChainRoot, 0);
      opaqueInputs.set(proofResult.amountCommitment, 32);
      opaqueInputs.set(proofResult.passwordHash, 64);

      // Generate random salt for commitment re-randomization (privacy: prevents deposit→claim linkage)
      const saltBytes = crypto.getRandomValues(new Uint8Array(32));

      // Pack opaque opening: amount(8 LE) + blinding_factor(32) + salt(32)
      const openingBuf = new Uint8Array(72);
      new DataView(openingBuf.buffer).setBigUint64(0, amount, true);
      openingBuf.set(bigintToBytes32BE(blindingFactor), 8);
      openingBuf.set(saltBytes, 40);

      if (claimMode === "relayer") {
        // Step 4a: Send claim_credit via relayer
        const claimResp = await fetch(`${RELAYER_URL}/api/relay/credit/claim`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            proof: {
              proofA: Array.from(proofResult.proofA),
              proofB: Array.from(proofResult.proofB),
              proofC: Array.from(proofResult.proofC),
            },
            nullifierHash: Array.from(nullifierHashBytes),
            recipient: publicKey!.toBase58(),
            inputs: Array.from(opaqueInputs),
            salt: Array.from(saltBytes),
          }),
        });
        const claimResult = await claimResp.json();
        if (!claimResp.ok) throw new Error(claimResult.error || "Relayer rejected claim");

        // Step 4: Send withdraw_credit via relayer
        setStage("withdrawing");
        const withdrawResp = await fetch(`${RELAYER_URL}/api/relay/credit/withdraw`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            nullifierHash: Array.from(nullifierHashBytes),
            opening: Array.from(openingBuf),
            recipient: publicKey!.toBase58(),
          }),
        });
        const withdrawResult = await withdrawResp.json();
        if (!withdrawResp.ok) throw new Error(withdrawResult.error || "Relayer rejected withdraw");

        const fee = (amount * BigInt(RELAYER_FEE_BPS)) / 10000n;
        const net = amount - fee;
        setClaimedAmount((Number(net) / 1e9).toFixed(4));
        setFeeAmount((Number(fee) / 1e9).toFixed(4));
        setClaimTxSig(claimResult.signature);
        setWithdrawTxSig(withdrawResult.signature);
      } else {
        // Direct claim: two TXs from wallet

        // TX 1: claim_credit (no SOL moves, ZK proof verified)
        const inputsLenBuf = new Uint8Array(4);
        new DataView(inputsLenBuf.buffer).setUint32(0, 96, true);

        const claimCreditData = new Uint8Array(
          8 + 32 + 64 + 128 + 64 + 4 + 96 + 32
        );
        let off = 0;
        claimCreditData.set(CLAIM_CREDIT_DISCRIMINATOR, off); off += 8;
        claimCreditData.set(nullifierHashBytes, off); off += 32;
        claimCreditData.set(proofResult.proofA, off); off += 64;
        claimCreditData.set(proofResult.proofB, off); off += 128;
        claimCreditData.set(proofResult.proofC, off); off += 64;
        claimCreditData.set(inputsLenBuf, off); off += 4;
        claimCreditData.set(opaqueInputs, off); off += 96;
        claimCreditData.set(saltBytes, off);

        const claimCreditIx = new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: vault, isSigner: false, isWritable: true },
            { pubkey: merkleTree, isSigner: false, isWritable: false },
            { pubkey: creditNotePDA, isSigner: false, isWritable: true },
            { pubkey: nullifierPDA, isSigner: false, isWritable: true },
            { pubkey: publicKey!, isSigner: false, isWritable: false },
            { pubkey: publicKey!, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
          data: Buffer.from(claimCreditData),
        });

        const tx1 = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
          claimCreditIx
        );
        const sig1 = await sendTransaction!(tx1, connection);
        await connection.confirmTransaction(sig1, "confirmed");

        // TX 2: withdraw_credit (SOL moves via direct lamport manipulation)
        setStage("withdrawing");
        const openingLenBuf = new Uint8Array(4);
        new DataView(openingLenBuf.buffer).setUint32(0, 72, true);
        const rateBuf = new Uint8Array(2); // rate = 0 for direct

        const withdrawData = new Uint8Array(8 + 32 + 4 + 72 + 2);
        off = 0;
        withdrawData.set(WITHDRAW_CREDIT_DISCRIMINATOR, off); off += 8;
        withdrawData.set(nullifierHashBytes, off); off += 32;
        withdrawData.set(openingLenBuf, off); off += 4;
        withdrawData.set(openingBuf, off); off += 40;
        withdrawData.set(rateBuf, off);

        const withdrawIx = new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: vault, isSigner: false, isWritable: true },
            { pubkey: treasury, isSigner: false, isWritable: true },
            { pubkey: creditNotePDA, isSigner: false, isWritable: true },
            { pubkey: publicKey!, isSigner: false, isWritable: true },    // recipient
            { pubkey: publicKey!, isSigner: false, isWritable: true },    // fee_recipient
            { pubkey: publicKey!, isSigner: true, isWritable: true },     // payer
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
          data: Buffer.from(withdrawData),
        });

        const tx2 = new Transaction().add(withdrawIx);
        const sig2 = await sendTransaction!(tx2, connection);
        await connection.confirmTransaction(sig2, "confirmed");

        setClaimedAmount(amountSol.toFixed(4));
        setFeeAmount("");
        setClaimTxSig(sig1);
        setWithdrawTxSig(sig2);
      }

      setStage("done");
    } catch (err: any) {
      console.error("Claim failed:", err);
      setError(err.message || "Claim failed");
      setStage("error");
    }
  };

  return (
    <div className="mx-auto w-full max-w-xl px-4 sm:px-6 pb-20" style={{ paddingTop: "80px" }}>
      <div className="mb-8">
        <p className="mb-2 font-mono text-[9px] tracking-[0.3em] text-[rgba(0,255,65,0.35)]">
          OUTPUT // 0X02
        </p>
        <h1 className="font-mono text-[clamp(24px,4vw,36px)] font-light leading-[1.15] text-[var(--text)]">
          Claim a<br />dead drop.
        </h1>
        <p className="mt-3 text-xs leading-relaxed text-[rgba(224,224,224,0.45)]">
          Paste the claim code. A ZK proof is generated in your browser and verified on-chain.
        </p>
      </div>

        {(stage === "idle" || stage === "error") ? (
          <div className="space-y-3">
            {/* Claim code */}
            <div className="border border-[rgba(0,255,65,0.1)] bg-[#050505]">
              <div className="border-b border-[rgba(0,255,65,0.1)] px-5 py-3">
                <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.2)]">CLAIM CODE</span>
              </div>
              <div className="p-4">
                <textarea
                  value={claimCode}
                  onChange={(e) => setClaimCode(e.target.value)}
                  placeholder="darkdrop:v4:devnet:sol:raw:..."
                  rows={3}
                  className="w-full text-[var(--accent)] text-[11px] sm:text-xs font-mono resize-none overflow-y-auto overflow-x-hidden break-all"
                />
              </div>
            </div>

            {/* Password */}
            <div className="border border-[rgba(0,255,65,0.1)] bg-[#050505]">
              <div className="border-b border-[rgba(0,255,65,0.1)] px-5 py-3">
                <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.2)]">PASSWORD (IF REQUIRED)</span>
              </div>
              <div className="p-4">
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Leave empty if none"
                  className="w-full text-sm font-mono"
                />
              </div>
            </div>

            {/* Claim method */}
            <div className="border border-[rgba(0,255,65,0.1)] bg-[#050505]">
              <div className="border-b border-[rgba(0,255,65,0.1)] px-5 py-3 flex items-center justify-between">
                <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.2)]">CLAIM METHOD</span>
                {relayerOnline !== null && (
                  <span className={`font-mono text-[8px] tracking-[0.12em] flex items-center gap-1.5 ${relayerOnline ? "text-[rgba(0,255,65,0.5)]" : "text-[rgba(224,224,224,0.25)]"}`}>
                    <span className={`inline-block h-1.5 w-1.5 rounded-full ${relayerOnline ? "bg-[var(--accent)] shadow-[0_0_4px_var(--accent)]" : "bg-[rgba(224,224,224,0.2)]"}`} />
                    {relayerOnline ? "RELAYER: ONLINE" : "RELAYER: OFFLINE"}
                  </span>
                )}
              </div>
              <div className="p-4 space-y-2">
                <button
                  type="button"
                  onClick={() => setClaimMode("relayer")}
                  className={`flex w-full items-start gap-3 border p-4 text-left transition-colors ${
                    claimMode === "relayer"
                      ? "border-[rgba(0,255,65,0.4)] bg-[rgba(0,255,65,0.04)]"
                      : "border-[rgba(0,255,65,0.1)] hover:border-[rgba(0,255,65,0.25)]"
                  }`}
                >
                  <span className={`mt-0.5 flex h-3 w-3 items-center justify-center rounded-full border ${
                    claimMode === "relayer"
                      ? "border-[var(--accent)]"
                      : "border-[rgba(224,224,224,0.2)]"
                  }`}>
                    {claimMode === "relayer" && <span className="block h-1.5 w-1.5 rounded-full bg-[var(--accent)]" />}
                  </span>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-[10px] tracking-[0.12em] ${
                        claimMode === "relayer" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                      }`}>GASLESS</span>
                      <span className="border border-[rgba(0,255,65,0.2)] px-1.5 py-0.5 font-mono text-[8px] tracking-[0.15em] text-[rgba(0,255,65,0.4)]">0.5% FEE</span>
                    </div>
                    <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                      Relayer pays gas. Your wallet only appears as recipient, not as signer or fee payer.
                    </p>
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => setClaimMode("direct")}
                  className={`flex w-full items-start gap-3 border p-4 text-left transition-colors ${
                    claimMode === "direct"
                      ? "border-[rgba(0,255,65,0.4)] bg-[rgba(0,255,65,0.04)]"
                      : "border-[rgba(0,255,65,0.1)] hover:border-[rgba(0,255,65,0.25)]"
                  }`}
                >
                  <span className={`mt-0.5 flex h-3 w-3 items-center justify-center rounded-full border ${
                    claimMode === "direct"
                      ? "border-[var(--accent)]"
                      : "border-[rgba(224,224,224,0.2)]"
                  }`}>
                    {claimMode === "direct" && <span className="block h-1.5 w-1.5 rounded-full bg-[var(--accent)]" />}
                  </span>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-[10px] tracking-[0.12em] ${
                        claimMode === "direct" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                      }`}>DIRECT</span>
                      <span className="border border-[rgba(0,255,65,0.2)] px-1.5 py-0.5 font-mono text-[8px] tracking-[0.15em] text-[rgba(0,255,65,0.4)]">PAY GAS</span>
                    </div>
                    <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                      You pay gas directly. Your wallet appears as both payer and recipient.
                    </p>
                  </div>
                </button>
              </div>
            </div>

            {!publicKey && (
              <div className="border border-[rgba(0,255,65,0.1)] bg-[#050505] p-4 text-center text-[10px] text-[rgba(224,224,224,0.3)]">
                Connect wallet to set your recipient address.
              </div>
            )}

            {error && (
              <div className="border border-[rgba(255,0,68,0.2)] bg-[rgba(255,0,68,0.04)] px-5 py-3">
                <p className="text-xs text-[var(--danger)]">{error}</p>
              </div>
            )}

            <button
              onClick={handleClaim}
              disabled={!claimCode || !publicKey}
              className="w-full border border-[var(--accent)] bg-[var(--accent)] py-3 font-mono text-[10px] font-medium tracking-[0.2em] !text-black transition-all hover:bg-[#33ff66] hover:shadow-[0_0_24px_rgba(0,255,65,0.25)] disabled:opacity-30 disabled:cursor-not-allowed"
            >
              {claimMode === "relayer" ? "CLAIM (GASLESS)" : "CLAIM (DIRECT)"}
            </button>
          </div>
        ) : stage === "done" ? (
          <div className="space-y-4">
            <div className="border border-[rgba(0,255,65,0.2)] bg-[#050505] p-8 text-center">
              <p className="font-mono text-[clamp(28px,4vw,40px)] font-light text-[var(--accent)] mb-2">
                {claimedAmount} SOL
              </p>
              <p className="text-xs text-[rgba(224,224,224,0.5)]">Successfully claimed</p>
              {feeAmount && (
                <p className="mt-1 text-[10px] text-[rgba(224,224,224,0.3)]">
                  Relayer fee: {feeAmount} SOL
                </p>
              )}
              <div className="mt-3 space-y-1">
                {claimTxSig && (
                  <a
                    href={`https://solscan.io/tx/${claimTxSig}?cluster=devnet`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block font-mono text-[10px] tracking-[0.1em] text-[rgba(0,255,65,0.5)] hover:text-[var(--accent)] transition-colors"
                  >
                    CLAIM TX &rarr; SOLSCAN
                  </a>
                )}
                {withdrawTxSig && (
                  <a
                    href={`https://solscan.io/tx/${withdrawTxSig}?cluster=devnet`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block font-mono text-[10px] tracking-[0.1em] text-[rgba(0,255,65,0.5)] hover:text-[var(--accent)] transition-colors"
                  >
                    WITHDRAW TX &rarr; SOLSCAN
                  </a>
                )}
              </div>
            </div>

            <button
              onClick={() => {
                setStage("idle");
                setClaimCode("");
                setPassword("");
                setClaimTxSig("");
                setWithdrawTxSig("");
                setFeeAmount("");
              }}
              className="w-full border border-[rgba(0,255,65,0.2)] py-3 font-mono text-[10px] tracking-[0.15em] text-[rgba(224,224,224,0.5)] transition-all hover:border-[rgba(0,255,65,0.4)] hover:text-[var(--text)]"
            >
              CLAIM ANOTHER
            </button>
          </div>
        ) : (
          <ProofProgress stage={stage} error={error} />
        )}
    </div>
  );
}

function computeZeroHashes(): bigint[] {
  const zeros: bigint[] = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    zeros.push(poseidonHash([zeros[i], zeros[i]]));
  }
  return zeros;
}
