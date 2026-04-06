use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::poseidon::poseidon_hash;

/// Append a leaf to the incremental Merkle tree.
/// Returns the Merkle proof (sibling hashes) for the inserted leaf.
///
/// Algorithm:
///   1. Start at the leaf level with the new leaf hash
///   2. For each level 0..depth:
///      - If current_index is even: this is a left child, sibling is zero hash
///        Store current_level_hash in filled_subtrees[level]
///      - If current_index is odd: this is a right child, sibling is filled_subtrees[level]
///      - Hash the pair: next_level = Poseidon(left, right)
///   3. Update root and root history
pub fn merkle_tree_append(
    tree: &mut MerkleTreeAccount,
    leaf: [u8; 32],
) -> Result<()> {
    let max_capacity = 1u32 << MERKLE_DEPTH;
    require!(tree.next_index < max_capacity, DarkDropError::TreeFull);

    let mut current_index = tree.next_index as usize;
    let mut current_level_hash = leaf;

    for i in 0..MERKLE_DEPTH {
        let (left, right) = if current_index % 2 == 0 {
            // Left child: sibling is the zero hash at this level
            tree.filled_subtrees[i] = current_level_hash;
            (current_level_hash, ZERO_HASHES[i])
        } else {
            // Right child: sibling is the stored subtree
            (tree.filled_subtrees[i], current_level_hash)
        };

        current_level_hash = poseidon_hash(&left, &right);
        current_index /= 2;
    }

    // Update root
    tree.current_root = current_level_hash;

    // Update root history (circular buffer)
    tree.root_history_index = (tree.root_history_index + 1) % ROOT_HISTORY_SIZE as u32;
    tree.root_history[tree.root_history_index as usize] = current_level_hash;

    // Increment leaf index
    tree.next_index = tree.next_index
        .checked_add(1)
        .ok_or(DarkDropError::Overflow)?;

    Ok(())
}
