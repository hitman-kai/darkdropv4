/**
 * DarkDrop V4 — Relayer Configuration
 */

export const config = {
  // Solana RPC
  rpcUrl: process.env.RPC_URL || "https://api.devnet.solana.com",

  // Relayer keypair path (fee payer)
  keypairPath:
    process.env.RELAYER_KEYPAIR || "~/.config/solana/relayer.json",

  // DarkDrop program ID
  programId: "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU",

  // Relay fee: percentage of claim amount (basis points, 100 = 1%)
  feeRateBps: parseInt(process.env.FEE_RATE_BPS || "50"), // 0.5% default

  // Server port
  port: parseInt(process.env.PORT || "3001"),

  // Rate limiting
  rateLimit: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 10, // per IP per window
  },

  // Max claim amount the relayer will process (in lamports)
  maxClaimAmount: BigInt(process.env.MAX_CLAIM || "100000000000"), // 100 SOL
};
