#!/usr/bin/env node
// Fetch a specific drand round and BLS-verify its signature against a pinned
// chain hash + group public key. Called by ceremony.sh during finalize.
//
// Usage:   node scripts/verify-drand.js <chain-hash> <public-key> <round>
// Stdout:  64-char hex randomness (no trailing newline)
// Stderr:  diagnostic messages on failure
// Exit:    0 on verified beacon, 1 on any failure
//
// Verification model:
//   - chainHash + publicKey are passed in chainVerificationParams. drand-client
//     fetches /<chainHash>/info and refuses to proceed unless BOTH the returned
//     `hash` field and `public_key` field match what we pinned. This pins the
//     chain identity AND the BLS group key against a substituted /info response.
//   - drand-client then BLS-verifies the beacon signature for the requested
//     round against the (now-trusted) group public key (disableBeaconVerification: false).
//   - If any step fails, fetchBeacon throws. We exit 1.
//
// This is what we use instead of `curl /public/latest | jq .randomness`, which
// lets the maintainer shop for finalization-favorable rounds and offers zero
// authenticity guarantees beyond TLS.

const { fetchBeacon, HttpChainClient, HttpCachingChain } = require('drand-client');

function die(msg) {
    process.stderr.write(`FATAL: ${msg}\n`);
    process.exit(1);
}

async function main() {
    const [chainHash, publicKey, roundArg] = process.argv.slice(2);
    if (!chainHash || !publicKey || !roundArg) {
        die('Usage: node scripts/verify-drand.js <chain-hash> <public-key> <round>');
    }
    if (!/^[0-9a-f]{64}$/.test(chainHash)) {
        die(`chainHash must be 64 hex chars, got: ${chainHash}`);
    }
    // BLS-on-BLS12-381-G1 public keys are 48 bytes / 96 hex chars (drand mainnet).
    if (!/^[0-9a-f]{96}$/.test(publicKey)) {
        die(`publicKey must be 96 hex chars (48 bytes G1), got length ${publicKey.length}`);
    }
    const round = Number.parseInt(roundArg, 10);
    if (!Number.isInteger(round) || round <= 0 || String(round) !== roundArg) {
        die(`round must be a positive integer, got: ${roundArg}`);
    }

    const options = {
        disableBeaconVerification: false,
        noCache: true,
        chainVerificationParams: { chainHash, publicKey },
    };

    const chain = new HttpCachingChain(`https://api.drand.sh/${chainHash}`, options);
    const client = new HttpChainClient(chain, options);

    let beacon;
    try {
        beacon = await fetchBeacon(client, round);
    } catch (err) {
        die(`fetch/verify of round ${round} on chain ${chainHash} failed: ${err && err.message ? err.message : err}`);
    }

    if (!beacon || typeof beacon.randomness !== 'string' || !/^[0-9a-f]{64}$/.test(beacon.randomness)) {
        die(`drand returned malformed beacon: ${JSON.stringify(beacon)}`);
    }
    if (beacon.round !== round) {
        die(`drand returned round ${beacon.round}, expected ${round}`);
    }

    process.stdout.write(beacon.randomness);
}

main().catch((err) => die(err && err.stack ? err.stack : String(err)));
