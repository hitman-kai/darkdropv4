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

    #[msg("Revoke attempted before timeout expired")]
    RevokeTooEarly,

    #[msg("Unauthorized revoke: signer is not the depositor")]
    UnauthorizedRevoke,

    #[msg("Drop already claimed or revoked")]
    DropAlreadyClaimed,

    #[msg("Invalid DepositReceipt account in create_drop remaining_accounts")]
    InvalidDepositReceipt,

    #[msg("A deposit receipt already exists for this leaf")]
    LeafAlreadyDeposited,
}
