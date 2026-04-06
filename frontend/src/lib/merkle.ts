/**
 * DarkDrop V4 — Client-side Merkle Tree
 *
 * Builds the Merkle tree from on-chain leaf data and computes
 * proof paths for claims.
 */

import { poseidonHash } from "./crypto";

const MERKLE_DEPTH = 20;

// Precomputed zero hashes — must match on-chain ZERO_HASHES and circuit.
// zeros[0] = 0n
// zeros[i+1] = Poseidon(zeros[i], zeros[i])
let ZERO_HASHES: bigint[] | null = null;

/**
 * Compute zero hashes lazily (requires Poseidon to be initialized).
 */
export function getZeroHashes(): bigint[] {
  if (ZERO_HASHES) return ZERO_HASHES;
  ZERO_HASHES = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    ZERO_HASHES.push(poseidonHash([ZERO_HASHES[i], ZERO_HASHES[i]]));
  }
  return ZERO_HASHES;
}

export interface MerkleProof {
  pathElements: bigint[];
  pathIndices: number[];
  root: bigint;
}

/**
 * Incremental Merkle tree matching the on-chain structure.
 *
 * Uses the same algorithm as merkle_tree.rs:
 *   - filled_subtrees[i] stores the hash at level i of the last left subtree
 *   - Insertions only touch one path (O(depth) operations)
 *   - root_history tracks recent roots
 */
export class IncrementalMerkleTree {
  private filledSubtrees: bigint[];
  private leaves: bigint[] = [];
  private nextIndex = 0;
  private currentRoot: bigint;
  private zeroHashes: bigint[];
  private layers: bigint[][] = [];

  constructor() {
    this.zeroHashes = getZeroHashes();
    this.filledSubtrees = this.zeroHashes.slice(0, MERKLE_DEPTH);
    this.currentRoot = this.zeroHashes[MERKLE_DEPTH];
  }

  get root(): bigint {
    return this.currentRoot;
  }

  get size(): number {
    return this.nextIndex;
  }

  /**
   * Insert a leaf into the tree. Mirrors on-chain merkle_tree_append.
   */
  insert(leaf: bigint): number {
    const index = this.nextIndex;
    if (index >= 2 ** MERKLE_DEPTH) {
      throw new Error("Merkle tree is full");
    }

    this.leaves.push(leaf);
    let currentIndex = index;
    let currentLevelHash = leaf;

    for (let i = 0; i < MERKLE_DEPTH; i++) {
      let left: bigint, right: bigint;
      if (currentIndex % 2 === 0) {
        left = currentLevelHash;
        right = this.zeroHashes[i];
        this.filledSubtrees[i] = currentLevelHash;
      } else {
        left = this.filledSubtrees[i];
        right = currentLevelHash;
      }
      currentLevelHash = poseidonHash([left, right]);
      currentIndex = Math.floor(currentIndex / 2);
    }

    this.currentRoot = currentLevelHash;
    this.nextIndex++;
    this.layers = []; // Invalidate cached layers
    return index;
  }

  /**
   * Get the Merkle proof for a leaf at the given index.
   * Rebuilds the full tree from leaves to compute sibling hashes.
   */
  getProof(leafIndex: number): MerkleProof {
    if (leafIndex >= this.nextIndex) {
      throw new Error(`Leaf index ${leafIndex} out of range (tree has ${this.nextIndex} leaves)`);
    }

    // Build full tree layers if not cached
    if (this.layers.length === 0) {
      this.buildLayers();
    }

    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];

    let idx = leafIndex;
    for (let d = 0; d < MERKLE_DEPTH; d++) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      pathElements.push(this.layers[d][siblingIdx] ?? this.zeroHashes[d]);
      pathIndices.push(idx % 2);
      idx = Math.floor(idx / 2);
    }

    return {
      pathElements,
      pathIndices,
      root: this.currentRoot,
    };
  }

  /**
   * Rebuild the tree from on-chain leaves (e.g., fetched from events).
   */
  static fromLeaves(leaves: bigint[]): IncrementalMerkleTree {
    const tree = new IncrementalMerkleTree();
    for (const leaf of leaves) {
      tree.insert(leaf);
    }
    return tree;
  }

  private buildLayers(): void {
    const zeroHashes = this.zeroHashes;

    // Level 0: all leaves, padded with zeros
    const level0: bigint[] = [...this.leaves];
    // Only pad up to the next power of 2 at each level as needed
    this.layers = [level0];

    let currentLayer = level0;
    for (let d = 0; d < MERKLE_DEPTH; d++) {
      const nextLayer: bigint[] = [];
      const layerSize = Math.ceil(currentLayer.length / 2);
      for (let i = 0; i < layerSize; i++) {
        const left = currentLayer[i * 2] ?? zeroHashes[d];
        const right = currentLayer[i * 2 + 1] ?? zeroHashes[d];
        nextLayer.push(poseidonHash([left, right]));
      }
      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }
}
