/**
 * DarkDrop V4 — Relayer Service
 *
 * Allows recipients to claim drops without holding SOL for gas.
 * The relayer submits the claim TX and deducts a small fee.
 *
 * The relayer is NOT a trust assumption:
 *   - Cannot steal funds (ZK proof binds to recipient)
 *   - Can only censor (refuse to relay)
 *   - If relayer is down, users can submit TX directly
 */

import express from "express";
import rateLimit from "express-rate-limit";
import cors from "cors";
import { Keypair } from "@solana/web3.js";
import { config } from "./config";
import { loadRelayerKeypair } from "./keypair";
import claimRouter from "./routes/claim";
import depositRouter from "./routes/deposit";
import creditRouter from "./routes/credit";
import poolRouter from "./routes/pool";
import poolClaimRouter from "./routes/pool-claim";

const app = express();

// Load keypair once at startup (not on every request)
let relayerKeypair: Keypair;
try {
  relayerKeypair = loadRelayerKeypair();
} catch (err: any) {
  console.error("Failed to load relayer keypair:", err.message);
  process.exit(1);
}

// Make keypair available to route handlers
app.locals.relayerKeypair = relayerKeypair;

app.set("trust proxy", 1);
app.use(cors({ origin: config.corsOrigin }));
app.use(express.json({ limit: "10kb" }));

// Rate limiting
app.use(
  "/api/relay",
  rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.maxRequests,
    message: { error: "Too many requests. Try again later." },
  })
);

// Health check
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    version: "v4.1",
    relayerPubkey: relayerKeypair.publicKey.toBase58(),
  });
});

// Relay endpoints
app.use("/api/relay/claim", claimRouter);
app.use("/api/relay/create-drop", depositRouter);
app.use("/api/relay/credit", creditRouter);
app.use("/api/relay/create-drop-to-pool", poolRouter);
app.use("/api/relay/pool/claim", poolClaimRouter);

app.listen(config.port, () => {
  console.log(`DarkDrop V4 Relayer running on port ${config.port}`);
  console.log(`RPC: ${config.rpcUrl}`);
  console.log(`Fee: ${config.feeRateBps} bps`);
  console.log(`CORS: ${config.corsOrigin}`);
  console.log(`Relayer: ${relayerKeypair.publicKey.toBase58()}`);
});
