/**
 * DarkDrop V4 — Client-side Merkle Tree
 *
 * Builds the Merkle tree from on-chain leaf data and computes
 * proof paths for claims.
 */

import { Connection, PublicKey } from "@solana/web3.js";
import { poseidonHash } from "./crypto";

const MERKLE_DEPTH = 20;

// sha256("event:DropCreated")[0..8]
const DROP_CREATED_EVENT_DISCRIMINATOR = new Uint8Array([
  179, 166, 43, 166, 63, 69, 138, 46,
]);

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

  /**
   * Fetch leaves from DropCreated event logs and replay the tree up to
   * `targetLeafIndex` (inclusive). Returns the Merkle proof for that leaf.
   *
   * The on-chain program accepts any root in its 30-slot root_history, so
   * the proof against the historical root at insertion time will verify.
   *
   * Scans signatures for the merkleTree PDA in reverse chronological order
   * and decodes Anchor events from `Program data:` log entries to recover
   * the authoritative (leaf_index, leaf) mapping. More reliable than
   * ordering by slot because leaf_index is emitted by the program itself.
   */
  static async fromOnChainEvents(
    connection: Connection,
    merkleTree: PublicKey,
    targetLeafIndex: number,
    options?: {
      pageLimit?: number;
      maxPages?: number;
      concurrency?: number;
      onProgress?: (found: number, target: number) => void;
    }
  ): Promise<MerkleProof> {
    const pageLimit = options?.pageLimit ?? 200;
    const maxPages = options?.maxPages ?? 20;
    const concurrency = options?.concurrency ?? 4;
    const onProgress = options?.onProgress;
    const leaves = new Map<number, bigint>();
    let before: string | undefined;

    const processTx = (
      tx: Awaited<ReturnType<Connection["getTransaction"]>>
    ) => {
      if (!tx?.meta?.logMessages) return;
      for (const msg of tx.meta.logMessages) {
        const decoded = decodeProgramDataLog(msg);
        if (!decoded) continue;
        if (!hasPrefix(decoded, DROP_CREATED_EVENT_DISCRIMINATOR)) continue;
        if (decoded.length < 8 + 4 + 32) continue;
        const body = decoded.subarray(8);
        const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
        const leafIndex = view.getUint32(0, true);
        const leafBytes = body.subarray(4, 4 + 32);
        leaves.set(leafIndex, bytesToBigIntBE(leafBytes));
      }
    };

    outer: for (let page = 0; page < maxPages; page++) {
      const sigs = await connection.getSignaturesForAddress(merkleTree, {
        limit: pageLimit,
        before,
      });
      if (sigs.length === 0) break;

      // Fetch in small concurrent chunks to stay under public RPC rate limits.
      for (let i = 0; i < sigs.length; i += concurrency) {
        const chunk = sigs.slice(i, i + concurrency);
        const txs = await Promise.all(
          chunk.map((s) =>
            connection
              .getTransaction(s.signature, {
                commitment: "confirmed",
                maxSupportedTransactionVersion: 0,
              })
              .catch(() => null)
          )
        );
        for (const tx of txs) processTx(tx);
        if (onProgress) onProgress(countContiguous(leaves), targetLeafIndex + 1);
        if (haveContiguousLeaves(leaves, targetLeafIndex)) break outer;
      }

      before = sigs[sigs.length - 1].signature;
      if (sigs.length < pageLimit) break;
    }

    if (!haveContiguousLeaves(leaves, targetLeafIndex)) {
      const have = countContiguous(leaves);
      throw new Error(
        `Could not recover leaves up to index ${targetLeafIndex} from event logs (have contiguous 0..${have - 1}). The tree may be larger than the log scan window.`
      );
    }

    const tree = new IncrementalMerkleTree();
    for (let i = 0; i <= targetLeafIndex; i++) {
      tree.insert(leaves.get(i)!);
    }
    return tree.getProof(targetLeafIndex);
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

// ─── tree snapshot (for embedding in claim codes) ──────────────────

// Account layouts:
//   v1 (ROOT_HISTORY_SIZE=30):  1680 bytes. filled_subtrees at offset 1040.
//   v2 (ROOT_HISTORY_SIZE=256): 8912 bytes. filled_subtrees at offset 8272.
// Detected via account data length so reads are correct across the
// deploy → migrate_schema_v2 window where the two layouts coexist.
const TREE_ACCOUNT_ROOT_OFFSET = 8 + 32 + 4 + 4; // 48

const TREE_LAYOUT_V1 = { size: 1680, rootHistorySize: 30, filledSubtreesOffset: 48 + 32 + 30 * 32 };
const TREE_LAYOUT_V2 = { size: 8912, rootHistorySize: 256, filledSubtreesOffset: 48 + 32 + 256 * 32 };

function detectTreeLayout(treeData: Uint8Array) {
  if (treeData.length === TREE_LAYOUT_V2.size) return TREE_LAYOUT_V2;
  if (treeData.length === TREE_LAYOUT_V1.size) return TREE_LAYOUT_V1;
  throw new Error(
    `Unrecognized MerkleTree account size: ${treeData.length} (expected ${TREE_LAYOUT_V1.size} or ${TREE_LAYOUT_V2.size})`
  );
}

/**
 * Read the merkle tree account data and snapshot root + filled_subtrees
 * into a 672-byte blob (base64url-encoded). Use this immediately after a
 * successful create_drop to embed in the claim code — no RPC scanning
 * needed at claim time. Tolerant of both v1 (30-slot) and v2 (256-slot)
 * root_history layouts.
 */
export function snapshotTreeAccount(treeData: Uint8Array): string {
  const layout = detectTreeLayout(treeData);
  const buf = new Uint8Array(32 + 20 * 32);
  buf.set(treeData.subarray(TREE_ACCOUNT_ROOT_OFFSET, TREE_ACCOUNT_ROOT_OFFSET + 32), 0);
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    buf.set(
      treeData.subarray(
        layout.filledSubtreesOffset + i * 32,
        layout.filledSubtreesOffset + (i + 1) * 32
      ),
      32 + i * 32
    );
  }
  return uint8ToBase64url(buf);
}

export interface TreeSnapshot {
  root: bigint;
  filledSubtrees: bigint[]; // length MERKLE_DEPTH
}

export function decodeTreeSnapshot(encoded: string): TreeSnapshot {
  const buf = base64urlToUint8(encoded);
  if (buf.length !== 32 + 20 * 32) {
    throw new Error(`Invalid tree snapshot: expected 672 bytes, got ${buf.length}`);
  }
  const root = bytesToBigIntBE(buf.subarray(0, 32));
  const filledSubtrees: bigint[] = [];
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    filledSubtrees.push(bytesToBigIntBE(buf.subarray(32 + i * 32, 32 + (i + 1) * 32)));
  }
  return { root, filledSubtrees };
}

/**
 * Build the Merkle proof for `leafIndex` using a snapshot of the tree
 * state taken immediately after the leaf's insertion. Correct because
 * at snapshot time our leaf was the latest, so:
 *   - bit=0 sibling is zeroHashes[i] (no leaf to our right yet)
 *   - bit=1 sibling is filled_subtrees[i] (unchanged during our insert)
 * The on-chain program accepts any root in root_history, so the
 * snapshot root verifies as long as no more than 30 deposits have
 * happened since.
 */
export function buildProofFromSnapshot(
  snapshot: TreeSnapshot,
  leafIndex: number
): MerkleProof {
  const zeroHashes = getZeroHashes();
  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];
  let idx = leafIndex;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    const bit = idx & 1;
    pathIndices.push(bit);
    pathElements.push(bit === 0 ? zeroHashes[i] : snapshot.filledSubtrees[i]);
    idx >>= 1;
  }
  return { pathElements, pathIndices, root: snapshot.root };
}

// ─── base64url helpers (duplicated from claim-code.ts to avoid circular imports) ──

function uint8ToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return globalThis.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToUint8(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "===".slice(0, (4 - (base64.length % 4)) % 4);
  const bin = globalThis.atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ─── helpers for fromOnChainEvents ─────────────────────────────────

function decodeProgramDataLog(msg: string): Uint8Array | null {
  const prefix = "Program data: ";
  if (!msg.startsWith(prefix)) return null;
  const b64 = msg.slice(prefix.length).trim();
  try {
    const bin = globalThis.atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function hasPrefix(buf: Uint8Array, prefix: Uint8Array): boolean {
  if (buf.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (buf[i] !== prefix[i]) return false;
  }
  return true;
}

function haveContiguousLeaves(leaves: Map<number, bigint>, upTo: number): boolean {
  for (let i = 0; i <= upTo; i++) {
    if (!leaves.has(i)) return false;
  }
  return true;
}

function countContiguous(leaves: Map<number, bigint>): number {
  let i = 0;
  while (leaves.has(i)) i++;
  return i;
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return BigInt("0x" + (hex || "0"));
}
