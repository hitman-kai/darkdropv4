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
import {
  getAssociatedTokenAddressSync,
  getAccount,
  createAssociatedTokenAccountInstruction,
  TokenAccountNotFoundError,
  TokenInvalidAccountOwnerError,
} from "@solana/spl-token";
import ProofProgress from "@/components/ProofProgress";

import {
  initPoseidon,
  poseidonHash,
  nullifierHash as computeNullifierHash,
  amountCommitment as computeAmountCommitment,
  bigintToBytes32BE,
  bytes32BEToBigint,
} from "@/lib/crypto";
import { decodeClaimCode } from "@/lib/claim-code";
import { generateClaimProofV2, generateClaimProofV3 } from "@/lib/proof";
import {
  IncrementalMerkleTree,
  buildProofFromSnapshot,
  decodeTreeSnapshot,
} from "@/lib/merkle";
import { sendWithRetry } from "@/lib/send-with-retry";
import {
  buildClaimFromNotePoolIx,
  getNotePoolTreePDA,
  getPoolCreditNotePDA,
} from "@/lib/note-pool";
import { randomFieldElement } from "@/lib/crypto";
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

const USDC_DECIMALS = 6;

/**
 * Format a USDC base-unit BigInt as a human string. Trims trailing zeros
 * and the trailing decimal point — "5000000n" → "5", "4975000n" → "4.975".
 */
function formatUsdcAmount(baseUnits: bigint): string {
  const denom = 10n ** BigInt(USDC_DECIMALS);
  const whole = baseUnits / denom;
  const frac = baseUnits % denom;
  if (frac === 0n) return whole.toString();
  const fracStr = frac
    .toString()
    .padStart(USDC_DECIMALS, "0")
    .replace(/0+$/, "");
  return fracStr ? `${whole.toString()}.${fracStr}` : whole.toString();
}

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
  // Asset label for the success display — "SOL" by default to preserve the
  // pre-USDC text. Set per-claim from `decoded.asset`.
  const [claimedAssetLabel, setClaimedAssetLabel] = useState<"SOL" | "USDC">("SOL");
  // When a USDC claim is blocked because the recipient ATA doesn't exist,
  // we stash the mint + derived ATA here so the error panel can show a
  // user-signed "create token account" button.
  const [needsAtaCreation, setNeedsAtaCreation] = useState<
    { mint: PublicKey; ata: PublicKey } | null
  >(null);
  const [creatingAta, setCreatingAta] = useState(false);
  const [relayerOnline, setRelayerOnline] = useState<boolean | null>(null);

  // Lightweight pre-decode of the claim-code prefix so the UI can react to
  // asset ("usdc" disables direct mode) before the user actually submits.
  // Does NOT verify the encoded payload — just splits the URI prefix.
  const codeAsset: "sol" | "usdc" | null = (() => {
    if (!claimCode.startsWith("darkdrop:v4:")) return null;
    const slot = claimCode.split(":")[3];
    return slot === "usdc" ? "usdc" : "sol";
  })();

  useEffect(() => {
    checkRelayerHealth().then((online) => {
      setRelayerOnline(online);
      setClaimMode(online ? "relayer" : "direct");
    });
  }, []);

  // USDC v1 ships relayer-only — direct mode would require client-side SPL
  // ix construction (claim_credit_spl + withdraw_credit_spl) plus the user
  // having a payer ATA, neither of which is implemented yet. Force relayer
  // mode whenever the pasted code parses as USDC.
  useEffect(() => {
    if (codeAsset === "usdc" && claimMode !== "relayer") {
      setClaimMode("relayer");
    }
  }, [codeAsset, claimMode]);

  /**
   * Create the recipient ATA for `mint`, signed by the connected wallet.
   * Called from the error-state "Create token account" button after a USDC
   * claim is blocked by a missing ATA. After success, calls handleClaim()
   * again to resume the claim from scratch — proof gen is fast enough that
   * a re-run is simpler than threading state to skip the early steps.
   */
  const handleCreateRecipientAta = async () => {
    if (!publicKey || !sendTransaction || !needsAtaCreation) return;
    setCreatingAta(true);
    setError("");
    try {
      const ix = createAssociatedTokenAccountInstruction(
        publicKey, // payer
        needsAtaCreation.ata,
        publicKey, // owner
        needsAtaCreation.mint
      );
      const tx = new Transaction().add(ix);
      await sendWithRetry({
        wallet: { sendTransaction },
        connection,
        transaction: tx,
      });
      setNeedsAtaCreation(null);
      setCreatingAta(false);
      // Resume the claim flow — proof gen re-runs but the ATA is now there.
      handleClaim();
    } catch (e: any) {
      console.error("Create ATA failed:", e?.message || e);
      setError(e?.message || "Failed to create token account");
      setCreatingAta(false);
    }
  };

  /**
   * USDC claim path. Kept as a sibling function — `handleClaim` dispatches
   * here right after decoding when `decoded.asset === "usdc"`. The SOL code
   * path stays byte-identical to its pre-USDC form. USDC v1 ships
   * relayer-only (gasless); direct mode is gated upstream by a useEffect.
   *
   * Snapshot format: the SPL create-drop page emits the SAME 672-byte blob
   * format (root(32) || filled_subtrees[20*32]) that `decodeTreeSnapshot`
   * consumes — verified during the prior `parseUsdcAmount` task. So the
   * existing snapshot decode + proof builder work unchanged for SPL.
   */
  const handleClaimUsdc = async (
    decoded: Awaited<ReturnType<typeof decodeClaimCode>>,
    pwdBigint: bigint
  ) => {
    if (!publicKey) {
      setError("Connect your wallet so the relayer knows where to send funds.");
      setStage("error");
      return;
    }
    if (claimMode !== "relayer") {
      setError("Direct mode for USDC isn't available yet — please use Gasless.");
      setStage("error");
      return;
    }

    const mintStr = decoded.payload.mint;
    if (!mintStr) {
      setError("This USDC claim code is missing the mint field.");
      setStage("error");
      return;
    }
    const mint = new PublicKey(mintStr);

    // ATA pre-check. Cheap RPC, runs before the slow proof-gen so we don't
    // burn the user's time on a claim they can't finish.
    const recipientAta = getAssociatedTokenAddressSync(mint, publicKey);
    try {
      await getAccount(connection, recipientAta, "confirmed");
    } catch (e) {
      if (
        e instanceof TokenAccountNotFoundError ||
        e instanceof TokenInvalidAccountOwnerError
      ) {
        setNeedsAtaCreation({ mint, ata: recipientAta });
        setError(
          "You need a USDC token account before claiming. Creating one is a one-time ~0.002 SOL action."
        );
        setStage("error");
        return;
      }
      throw e;
    }

    const { secret, nullifier, amount, blindingFactor, leafIndex, pathSnapshot } =
      decoded.payload;

    setStage("merkle");
    if (!pathSnapshot) {
      throw new Error("USDC claim code missing pathSnapshot");
    }
    const snap = decodeTreeSnapshot(pathSnapshot);
    const merkleProofObj = buildProofFromSnapshot(snap, leafIndex);

    setStage("proving");
    const nullHash = computeNullifierHash(nullifier);
    const amtCommitment = computeAmountCommitment(amount, blindingFactor);
    const v2Result = await generateClaimProofV2(
      { secret, nullifier, amount, blindingFactor, password: pwdBigint },
      merkleProofObj,
      publicKey,
      nullHash,
      amtCommitment
    );

    const nullifierHashBytes = bigintToBytes32BE(nullHash);
    const onChainRoot = bigintToBytes32BE(merkleProofObj.root);

    // 64-byte opaque inputs: merkle_root || amount_commitment (password_hash removed, #20)
    const inputs = new Uint8Array(64);
    inputs.set(onChainRoot, 0);
    inputs.set(v2Result.amountCommitment, 32);

    // Random salt, reduced mod Fr — Poseidon panics on out-of-range field
    // elements, matching the SOL path's salt construction.
    const BN254_FR =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const saltRaw = crypto.getRandomValues(new Uint8Array(32));
    const saltReduced = bytes32BEToBigint(saltRaw) % BN254_FR;
    const saltBytes = bigintToBytes32BE(saltReduced);

    setStage("claiming");
    const claimResp = await fetch(`${RELAYER_URL}/api/relay/credit-spl/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mint: mint.toBase58(),
        proof: {
          proofA: Array.from(v2Result.proofA),
          proofB: Array.from(v2Result.proofB),
          proofC: Array.from(v2Result.proofC),
        },
        nullifierHash: Array.from(nullifierHashBytes),
        recipient: publicKey.toBase58(),
        inputs: Array.from(inputs),
        salt: Array.from(saltBytes),
      }),
    });
    const claimResult = await claimResp.json();
    if (!claimResp.ok) throw new Error(claimResult.error || "Relayer rejected claim");

    setStage("withdrawing");
    // Opening: amount(u64 LE, 8) || blinding(32) || salt(32). The program tries
    // the on-chain credit.salt first and falls back to this caller salt, which
    // is required for note-pool notes (Audit 06 M-02). Standard notes work with
    // either, so we keep sending the salt.
    const opening = new Uint8Array(72);
    new DataView(opening.buffer).setBigUint64(0, amount, true);
    opening.set(bigintToBytes32BE(blindingFactor), 8);
    opening.set(saltBytes, 40);

    const withdrawResp = await fetch(
      `${RELAYER_URL}/api/relay/credit-spl/withdraw`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mint: mint.toBase58(),
          nullifierHash: Array.from(nullifierHashBytes),
          opening: Array.from(opening),
          recipient: publicKey.toBase58(),
        }),
      }
    );
    const withdrawResult = await withdrawResp.json();
    if (!withdrawResp.ok) {
      // Race: the ATA was missing when the relayer evaluated. Surface a
      // recoverable error so the user can hit "create token account" and
      // retry — this is what the relayer 400 contract specifically signals.
      if (
        withdrawResp.status === 400 &&
        /Recipient ATA/i.test(withdrawResult.error || "")
      ) {
        setNeedsAtaCreation({ mint, ata: recipientAta });
      }
      throw new Error(withdrawResult.error || "Relayer rejected withdraw");
    }

    const fee = (amount * BigInt(RELAYER_FEE_BPS)) / 10000n;
    const net = amount - fee;
    // USDC at 6 decimals — use BigInt-aware string format that drops
    // trailing zeros. Number(...) / 1e6 is safe through 9 quadrillion base
    // units, far past our 100k USDC cap.
    setClaimedAmount(formatUsdcAmount(net));
    setFeeAmount(formatUsdcAmount(fee));
    setClaimedAssetLabel("USDC");
    setClaimTxSig(claimResult.signature);
    setWithdrawTxSig(withdrawResult.signature);
    setStage("done");
  };

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
      if ((encryption === "aes" || encryption === "pbkdf2") && !password) {
        setError("This drop is password-protected. Enter the password.");
        setStage("error");
        return;
      }

      const decoded = await decodeClaimCode(
        claimCode,
        (encryption === "aes" || encryption === "pbkdf2") ? password : undefined
      );

      // USDC branch — fully separate handler so the SOL path below stays
      // byte-identical. Pre-build pwdBigint (used by both branches) so the
      // USDC handler doesn't duplicate the password encoding logic.
      const pwdBigintShared = password
        ? BigInt(
            "0x" +
              Array.from(new TextEncoder().encode(password))
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("")
          )
        : 0n;
      if (decoded.asset === "usdc") {
        return handleClaimUsdc(decoded, pwdBigintShared);
      }

      const { secret, nullifier, amount, blindingFactor, leafIndex, pathSnapshot, flavor } =
        decoded.payload;
      const isPool = flavor === "pool";

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

      // Step 2: Build the Merkle proof. Prefer the snapshot embedded in the
      // claim code — zero RPC calls. Fall back to event-log replay only for
      // legacy claim codes without a snapshot (slow, may hit RPC limits).
      setStage("merkle");

      const [vault] = getVaultPDA();
      const [merkleTree] = getMerkleTreePDA(vault);
      const [notePoolTree] = getNotePoolTreePDA(vault);
      // Pool-flavored codes carry a snapshot of note_pool_tree; standard
      // codes carry a snapshot of merkle_tree. Same on-chain struct layout,
      // different PDA source.
      const treePdaForFlavor = isPool ? notePoolTree : merkleTree;

      let pathElements: bigint[];
      let pathIndices: number[];
      let merkleRootBigInt: bigint;

      if (pathSnapshot) {
        const snap = decodeTreeSnapshot(pathSnapshot);
        const proof = buildProofFromSnapshot(snap, leafIndex);
        pathElements = proof.pathElements;
        pathIndices = proof.pathIndices;
        merkleRootBigInt = proof.root;
      } else {
        const proof = await IncrementalMerkleTree.fromOnChainEvents(
          connection,
          treePdaForFlavor,
          leafIndex
        );
        pathElements = proof.pathElements;
        pathIndices = proof.pathIndices;
        merkleRootBigInt = proof.root;
      }

      const onChainRoot = bigintToBytes32BE(merkleRootBigInt);

      // Step 3: Generate ZK proof (V2 standard, V3 for pool flavor)
      setStage("proving");

      // Pool flavor generates fresh (blinding, salt) for the new CreditNote
      // that claim_from_note_pool will create — must be used in the
      // subsequent withdraw opening. Standard flavor keeps the code's
      // original blinding and picks a random salt.
      let nullifierHashBytes: Uint8Array;
      let opaqueInputs: Uint8Array;
      let saltBytes: Uint8Array;
      let withdrawBlinding: bigint;
      let poolV3Result: Awaited<ReturnType<typeof generateClaimProofV3>> | null = null;
      // V2 result populated only on standard flavor
      let v2ProofResult: Awaited<ReturnType<typeof generateClaimProofV2>> | null = null;

      if (isPool) {
        // V3 circuit: pool_secret/nullifier/blinding as the payload's
        // secret/nullifier/blindingFactor fields (semantic reuse).
        const newBlinding = randomFieldElement();
        const newSalt = randomFieldElement();
        const poolNullifierHashBig = computeNullifierHash(nullifier);
        poolV3Result = await generateClaimProofV3(
          {
            poolSecret: secret,
            poolNullifier: nullifier,
            poolBlinding: blindingFactor,
            amount,
          },
          { pathElements, pathIndices, root: merkleRootBigInt },
          publicKey!,
          poolNullifierHashBig,
          newBlinding,
          newSalt
        );
        nullifierHashBytes = poolV3Result.poolNullifierHash;
        // Pool claim ix opaque inputs: pool_root(32) + new_stored_commitment(32)
        opaqueInputs = new Uint8Array(64);
        opaqueInputs.set(poolV3Result.poolMerkleRoot, 0);
        opaqueInputs.set(poolV3Result.newStoredCommitment, 32);
        saltBytes = bigintToBytes32BE(newSalt);
        withdrawBlinding = newBlinding;
      } else {
        v2ProofResult = await generateClaimProofV2(
          { secret, nullifier, amount, blindingFactor, password: pwdBigint },
          { pathElements, pathIndices, root: merkleRootBigInt },
          publicKey!,
          nullHash,
          amtCommitment
        );
        nullifierHashBytes = bigintToBytes32BE(nullHash);
        opaqueInputs = new Uint8Array(64);
        opaqueInputs.set(onChainRoot, 0);
        opaqueInputs.set(v2ProofResult.amountCommitment, 32);
        // Random salt mod Fr — Poseidon panics on out-of-range inputs
        const BN254_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
        const saltRaw = crypto.getRandomValues(new Uint8Array(32));
        const saltReduced = bytes32BEToBigint(saltRaw) % BN254_FR;
        saltBytes = bigintToBytes32BE(saltReduced);
        withdrawBlinding = blindingFactor;
      }

      setStage("claiming");

      const [nullifierPDA] = getNullifierPDA(nullifierHashBytes);
      const [creditNotePDA] = isPool
        ? getPoolCreditNotePDA(nullifierHashBytes)
        : getCreditNotePDA(nullifierHashBytes);
      const [treasury] = getTreasuryPDA();

      // Withdraw opening: amount(8 LE) + blinding(32) + salt(32). Pool uses the
      // fresh (new_blinding, new_salt) from the V3 proof; standard uses the
      // code's blinding plus the random salt. The program tries on-chain
      // credit.salt first and falls back to this salt — the fallback is what
      // opens note-pool notes (Audit 06 M-02).
      const openingBuf = new Uint8Array(72);
      new DataView(openingBuf.buffer).setBigUint64(0, amount, true);
      openingBuf.set(bigintToBytes32BE(withdrawBlinding), 8);
      openingBuf.set(saltBytes, 40);

      // Flavor-independent proof bytes for downstream ix construction.
      const proofBytes = isPool
        ? { proofA: poolV3Result!.proofA, proofB: poolV3Result!.proofB, proofC: poolV3Result!.proofC }
        : { proofA: v2ProofResult!.proofA, proofB: v2ProofResult!.proofB, proofC: v2ProofResult!.proofC };

      if (claimMode === "relayer") {
        // Send claim via relayer. Pool flavor uses a different endpoint
        // because the V3 ix takes fewer public inputs (no separate salt
        // argument — it's baked into the proof commitment).
        const claimEndpoint = isPool
          ? `${RELAYER_URL}/api/relay/pool/claim`
          : `${RELAYER_URL}/api/relay/credit/claim`;
        const claimBody = isPool
          ? {
              proof: {
                proofA: Array.from(proofBytes.proofA),
                proofB: Array.from(proofBytes.proofB),
                proofC: Array.from(proofBytes.proofC),
              },
              poolNullifierHash: Array.from(nullifierHashBytes),
              recipient: publicKey!.toBase58(),
              inputs: Array.from(opaqueInputs),
            }
          : {
              proof: {
                proofA: Array.from(proofBytes.proofA),
                proofB: Array.from(proofBytes.proofB),
                proofC: Array.from(proofBytes.proofC),
              },
              nullifierHash: Array.from(nullifierHashBytes),
              recipient: publicKey!.toBase58(),
              inputs: Array.from(opaqueInputs),
              salt: Array.from(saltBytes),
            };
        const claimResp = await fetch(claimEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(claimBody),
        });
        const claimResult = await claimResp.json();
        if (!claimResp.ok) throw new Error(claimResult.error || "Relayer rejected claim");

        // Send withdraw_credit via relayer
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
        setClaimedAssetLabel("SOL");
        setClaimTxSig(claimResult.signature);
        setWithdrawTxSig(withdrawResult.signature);
      } else {
        // Direct claim: two TXs from wallet

        // TX 1: claim_credit or claim_from_note_pool depending on flavor.
        // Both produce a CreditNote at [b"credit", nullifier_hash] (or
        // pool_nullifier_hash for pool flavor); the subsequent withdraw
        // is shape-identical for both.
        let claimIx: TransactionInstruction;
        if (isPool) {
          claimIx = buildClaimFromNotePoolIx({
            payer: publicKey!,
            recipient: publicKey!,
            poolNullifierHashBytes: nullifierHashBytes,
            proofA: proofBytes.proofA,
            proofB: proofBytes.proofB,
            proofC: proofBytes.proofC,
            opaqueInputs,
          });
        } else {
          const inputsLenBuf = new Uint8Array(4);
          new DataView(inputsLenBuf.buffer).setUint32(0, 96, true);
          const claimCreditData = new Uint8Array(8 + 32 + 64 + 128 + 64 + 4 + 96 + 32);
          let off = 0;
          claimCreditData.set(CLAIM_CREDIT_DISCRIMINATOR, off); off += 8;
          claimCreditData.set(nullifierHashBytes, off); off += 32;
          claimCreditData.set(proofBytes.proofA, off); off += 64;
          claimCreditData.set(proofBytes.proofB, off); off += 128;
          claimCreditData.set(proofBytes.proofC, off); off += 64;
          claimCreditData.set(inputsLenBuf, off); off += 4;
          claimCreditData.set(opaqueInputs, off); off += 96;
          claimCreditData.set(saltBytes, off);
          claimIx = new TransactionInstruction({
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
        }

        const tx1 = new Transaction().add(
          ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
          claimIx
        );
        const sig1 = await sendWithRetry({
          wallet: { sendTransaction: sendTransaction! },
          connection,
          transaction: tx1,
        });

        // TX 2: withdraw_credit (SOL moves via direct lamport manipulation)
        // Opening is 72 bytes (amount + blinding + salt); program tries on-chain
        // credit.salt first, falls back to this salt for pool notes (Audit 06 M-02).
        setStage("withdrawing");
        const openingLenBuf = new Uint8Array(4);
        new DataView(openingLenBuf.buffer).setUint32(0, 72, true);
        const rateBuf = new Uint8Array(2); // rate = 0 for direct

        const withdrawData = new Uint8Array(8 + 32 + 4 + 72 + 2);
        let off = 0;
        withdrawData.set(WITHDRAW_CREDIT_DISCRIMINATOR, off); off += 8;
        withdrawData.set(nullifierHashBytes, off); off += 32;
        withdrawData.set(openingLenBuf, off); off += 4;
        withdrawData.set(openingBuf, off); off += 72;
        withdrawData.set(rateBuf, off);

        const withdrawIx = new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: vault, isSigner: false, isWritable: true },
            { pubkey: treasury, isSigner: false, isWritable: true },
            { pubkey: creditNotePDA, isSigner: false, isWritable: true },
            { pubkey: publicKey!, isSigner: false, isWritable: true },    // recipient
            { pubkey: publicKey!, isSigner: true, isWritable: true },     // payer (also fee recipient after I-04)
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
          data: Buffer.from(withdrawData),
        });

        const tx2 = new Transaction().add(withdrawIx);
        const sig2 = await sendTransaction!(tx2, connection);
        await connection.confirmTransaction(sig2, "confirmed");

        setClaimedAmount(amountSol.toFixed(4));
        setFeeAmount("");
        setClaimedAssetLabel("SOL");
        setClaimTxSig(sig1);
        setWithdrawTxSig(sig2);
      }

      setStage("done");
    } catch (err: any) {
      console.error("Claim failed:", err);
      // Raw runtime exceptions (e.g. a TypeError from a malformed claim code or
      // an undefined field) would otherwise leak internal JS messages into the
      // UI. Surface a sanitized, human-readable message for those; intentional
      // errors (insufficient funds, already claimed, decoder validation, …)
      // carry a meaningful message and are shown as-is.
      const isRawRuntimeError =
        err instanceof TypeError ||
        err instanceof RangeError ||
        err instanceof ReferenceError ||
        err instanceof SyntaxError;
      setError(
        isRawRuntimeError || !err?.message
          ? "Invalid or corrupted claim code, or an unexpected error occurred. Please double-check your code and try again."
          : err.message
      );
      setStage("error");
    }
  };

  return (
    <div className="mx-auto w-full max-w-xl px-4 sm:px-6 pb-20" style={{ paddingTop: "80px" }}>
      <div className="mb-8">
        <p className="mb-2 font-mono text-[9px] tracking-[0.3em] text-[var(--accent-dim)]">
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
          <div className="space-y-4">
            {/* Claim code */}
            <div className="arcade-panel">
              <div className="arcade-panel-header justify-between">
                <div className="flex items-center gap-3">
                  <span className="arcade-dot" />
                  <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">CLAIM CODE</span>
                </div>
                {codeAsset !== null && (
                  <span className="font-mono text-[8px] tracking-[0.12em] text-[rgba(0,255,65,0.5)]">
                    ASSET: {codeAsset === "usdc" ? "USDC" : "SOL"}
                  </span>
                )}
              </div>
              <div className="arcade-panel-body">
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
            <div className="arcade-panel">
              <div className="arcade-panel-header">
                <span className="arcade-dot" />
                <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">PASSWORD (IF REQUIRED)</span>
              </div>
              <div className="arcade-panel-body">
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
            <div className="arcade-panel">
              <div className="arcade-panel-header justify-between">
                <div className="flex items-center gap-3">
                  <span className="arcade-dot" />
                  <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">CLAIM METHOD</span>
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
                  onClick={() => relayerOnline && setClaimMode("relayer")}
                  disabled={!relayerOnline}
                  className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                    claimMode === "relayer"
                      ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                      : "border-[var(--border-dim)] hover:border-[var(--border)]"
                  } ${!relayerOnline ? "opacity-40 !cursor-not-allowed" : ""}`}
                >
                  <span className={`mt-0.5 flex h-4 w-4 items-center justify-center border-2 ${
                    claimMode === "relayer"
                      ? "border-[var(--accent)]"
                      : "border-[rgba(224,224,224,0.2)]"
                  }`}>
                    {claimMode === "relayer" && <span className="block h-2 w-2 bg-[var(--accent)]" />}
                  </span>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-[10px] tracking-[0.12em] font-semibold ${
                        claimMode === "relayer" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                      }`}>GASLESS</span>
                      <span className="arcade-badge">0.5% FEE</span>
                    </div>
                    <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                      Relayer pays gas. Your wallet only appears as recipient, not as signer or fee payer.
                    </p>
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => codeAsset !== "usdc" && setClaimMode("direct")}
                  disabled={codeAsset === "usdc"}
                  className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                    claimMode === "direct"
                      ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                      : "border-[var(--border-dim)] hover:border-[var(--border)]"
                  } ${codeAsset === "usdc" ? "opacity-40 !cursor-not-allowed" : ""}`}
                >
                  <span className={`mt-0.5 flex h-4 w-4 items-center justify-center border-2 ${
                    claimMode === "direct"
                      ? "border-[var(--accent)]"
                      : "border-[rgba(224,224,224,0.2)]"
                  }`}>
                    {claimMode === "direct" && <span className="block h-2 w-2 bg-[var(--accent)]" />}
                  </span>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-[10px] tracking-[0.12em] font-semibold ${
                        claimMode === "direct" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                      }`}>DIRECT</span>
                      <span className="arcade-badge">PAY GAS</span>
                    </div>
                    <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                      {codeAsset === "usdc"
                        ? "Not yet available for USDC — use Gasless."
                        : "You pay gas directly. Your wallet appears as both payer and recipient."}
                    </p>
                  </div>
                </button>
              </div>
            </div>

            {!publicKey && (
              <div className="arcade-panel">
                <div className="arcade-panel-body text-center text-[10px] text-[rgba(224,224,224,0.3)]">
                  Connect wallet to set your recipient address.
                </div>
              </div>
            )}

            {error && (
              <div className="border-2 border-[rgba(255,0,68,0.3)] bg-[rgba(255,0,68,0.04)] px-5 py-3 shadow-[2px_2px_0_rgba(255,0,68,0.2)]">
                <p className="text-xs text-[var(--danger)] font-semibold">{error}</p>
                {needsAtaCreation && (
                  <button
                    type="button"
                    onClick={handleCreateRecipientAta}
                    disabled={creatingAta || !publicKey}
                    className="arcade-btn-primary mt-3 w-full py-2.5 font-mono text-[10px] tracking-[0.2em]"
                  >
                    {creatingAta ? "CREATING TOKEN ACCOUNT…" : "CREATE USDC TOKEN ACCOUNT"}
                  </button>
                )}
              </div>
            )}

            <button
              onClick={handleClaim}
              disabled={!claimCode || !publicKey}
              className="arcade-btn-primary w-full py-3.5 font-mono text-[10px] tracking-[0.2em]"
            >
              {claimMode === "relayer" ? "CLAIM (GASLESS)" : "CLAIM (DIRECT)"}
            </button>
          </div>
        ) : stage === "done" ? (
          <div className="space-y-4">
            <div className="arcade-panel arcade-glow">
              <div className="arcade-panel-header justify-center">
                <span className="arcade-dot" />
                <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(0,255,65,0.6)]">CLAIMED</span>
              </div>
              <div className="arcade-panel-body text-center">
                <p className="font-mono text-[clamp(28px,4vw,40px)] font-light text-[var(--accent)] mb-2">
                  {claimedAmount} {claimedAssetLabel}
                </p>
                <p className="text-xs text-[rgba(224,224,224,0.5)]">Successfully claimed</p>
                {feeAmount && (
                  <p className="mt-1 text-[10px] text-[rgba(224,224,224,0.3)]">
                    Relayer fee: {feeAmount} {claimedAssetLabel}
                  </p>
                )}
                <div className="mt-4 space-y-1">
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
            </div>

            <button
              onClick={() => {
                setStage("idle");
                setClaimCode("");
                setPassword("");
                setClaimTxSig("");
                setWithdrawTxSig("");
                setFeeAmount("");
                setNeedsAtaCreation(null);
              }}
              className="arcade-btn-ghost w-full py-3 font-mono text-[10px] tracking-[0.15em]"
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
