use light_hasher::{Hasher, Poseidon};

/// Compute Poseidon hash of two 32-byte inputs.
/// Used for Merkle tree interior nodes: hash(left, right).
pub fn poseidon_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[left, right]).unwrap()
}

/// Get zero hashes for each level of the Merkle tree.
/// zero[0] = 0x00..00
/// zero[i+1] = Poseidon(zero[i], zero[i])
pub fn zero_hashes() -> Vec<[u8; 32]> {
    Poseidon::zero_bytes().to_vec()
}
