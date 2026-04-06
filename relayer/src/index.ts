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
import { config } from "./config";
import claimRouter from "./routes/claim";
import depositRouter from "./routes/deposit";
import creditRouter from "./routes/credit";

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Rate limiting
app.use(
  "/api/relay",
  rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.maxRequests,
    message: { error: "Too many requests. Try again later." },
  })
);

// Health check — includes relayer pubkey for private deposit flow
app.get("/health", (_req, res) => {
  try {
    const keypairPath = config.keypairPath.replace("~", require("os").homedir());
    const secretKey = JSON.parse(require("fs").readFileSync(keypairPath, "utf8"));
    const { Keypair } = require("@solana/web3.js");
    const relayer = Keypair.fromSecretKey(new Uint8Array(secretKey));
    res.json({ status: "ok", version: "v4.1", relayerPubkey: relayer.publicKey.toBase58() });
  } catch {
    res.json({ status: "ok", version: "v4.1" });
  }
});

// Relay endpoints
app.use("/api/relay/claim", claimRouter);
app.use("/api/relay/create-drop", depositRouter);
app.use("/api/relay/credit", creditRouter);

app.listen(config.port, () => {
  console.log(`DarkDrop V4 Relayer running on port ${config.port}`);
  console.log(`RPC: ${config.rpcUrl}`);
  console.log(`Fee: ${config.feeRateBps} bps`);
});
