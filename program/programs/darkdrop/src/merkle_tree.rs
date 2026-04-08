use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::poseidon::poseidon_hash;

/// Append a leaf to the incremental Merkle tree (main DarkDrop tree).
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
            tree.filled_subtrees[i] = current_level_hash;
            (current_level_hash, ZERO_HASHES[i])
        } else {
            (tree.filled_subtrees[i], current_level_hash)
        };

        current_level_hash = poseidon_hash(&left, &right);
        current_index /= 2;
    }

    tree.current_root = current_level_hash;
    tree.root_history_index = (tree.root_history_index + 1) % ROOT_HISTORY_SIZE as u32;
    tree.root_history[tree.root_history_index as usize] = current_level_hash;
    tree.next_index = tree.next_index
        .checked_add(1)
        .ok_or(DarkDropError::Overflow)?;

    Ok(())
}

/// Append a leaf to the note pool Merkle tree (second-layer mixer).
/// Same algorithm as merkle_tree_append but operates on NotePoolTree.
pub fn note_pool_tree_append(
    tree: &mut NotePoolTree,
    leaf: [u8; 32],
) -> Result<()> {
    let max_capacity = 1u32 << MERKLE_DEPTH;
    require!(tree.next_index < max_capacity, DarkDropError::TreeFull);

    let mut current_index = tree.next_index as usize;
    let mut current_level_hash = leaf;

    for i in 0..MERKLE_DEPTH {
        let (left, right) = if current_index % 2 == 0 {
            tree.filled_subtrees[i] = current_level_hash;
            (current_level_hash, ZERO_HASHES[i])
        } else {
            (tree.filled_subtrees[i], current_level_hash)
        };

        current_level_hash = poseidon_hash(&left, &right);
        current_index /= 2;
    }

    tree.current_root = current_level_hash;
    tree.root_history_index = (tree.root_history_index + 1) % ROOT_HISTORY_SIZE as u32;
    tree.root_history[tree.root_history_index as usize] = current_level_hash;
    tree.next_index = tree.next_index
        .checked_add(1)
        .ok_or(DarkDropError::Overflow)?;

    Ok(())
}
