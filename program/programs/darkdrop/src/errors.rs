use anchor_lang::prelude::*;

#[error_code]
pub enum DarkDropError {
    #[msg("Merkle tree is full")]
    TreeFull,

    #[msg("Invalid Merkle root — not found in root history")]
    InvalidRoot,

    #[msg("Nullifier has already been spent")]
    NullifierAlreadySpent,

    #[msg("Invalid ZK proof")]
    InvalidProof,

    #[msg("Amount exceeds drop cap")]
    AmountExceedsCap,

    #[msg("Amount must be greater than zero")]
    ZeroAmount,

    #[msg("Arithmetic overflow")]
    Overflow,

    #[msg("Insufficient vault balance")]
    InsufficientBalance,

    #[msg("Fee exceeds claim amount")]
    FeeTooHigh,

    #[msg("Commitment verification failed")]
    CommitmentMismatch,

    #[msg("Unauthorized withdrawal")]
    UnauthorizedWithdraw,

    #[msg("Invalid input data length")]
    InvalidInputLength,

    #[msg("Amount below minimum deposit")]
    BelowMinDeposit,

    #[msg("Vault already migrated")]
    AlreadyMigrated,
}
