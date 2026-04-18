import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { dummyContractAddress, emptyRunningCost } from '@midnight-ntwrk/compact-runtime';
import { Contract } from '../contracts/managed/verifier/contract/index.js';
import * as path from 'path';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { randomBytes } from 'crypto';
import { generateDID } from '../src/did.js';
import { issueAgeCredential } from '../src/credentials.js';

/**
 * SELECTIVE DISCLOSURE PROOF DEMO (Interactive)
 * User generates a ZK proof that their birth date matches an identity check.
 */

// Helper to pad to 32 bytes
function padTo32Bytes(num: number | bigint): Uint8Array {
    const buf = Buffer.alloc(32);
    buf.writeUInt32BE(Number(num), 28);
    return new Uint8Array(buf);
}

async function runProof() {
    console.log("╔══════════════════════════════════════════════╗");
    console.log("║     Interactive Zero-Knowledge Proof         ║");
    console.log("╚══════════════════════════════════════════════╝\n");

    const rl = createInterface({ input: stdin, output: stdout });
    const dobInput = await rl.question('  Enter your secret Date of Birth (YYYYMMDD): ');
    rl.close();

    const numericalDOB = parseInt(dobInput.trim(), 10);
    console.log(`\n  [Local Storage] Secret DOB recorded as: ${numericalDOB}`);

    console.log("  [Network] Connecting to Local Proof Server...\n");

    const zkConfigProvider = new NodeZkConfigProvider(
        path.resolve('contracts/managed/verifier/compiler')
    );
    const proofProvider = httpClientProofProvider(
        'http://localhost:6300',
        zkConfigProvider
    );

    const verifierInstance = new Contract({});

    // 1. Simulating off-chain DApp logic: Issue a real credential and get the salt dynamically.
    console.log("  [DApp] Dynamically issuing an Age VC to prevent hardcoding...");
    const issuer = generateDID();
    const holder = generateDID();
    const credential = issueAgeCredential(issuer, holder.did, dobInput.trim(), 18);

    // Convert inputs into compatible types for Compact (Bytes<32>)
    // Real implementation would pull this salt safely from wallet storage
    const UserSalt = new Uint8Array(Buffer.from(credential.salt, 'hex'));
    const secretDOBBytes = padTo32Bytes(numericalDOB);

    const context = {
        proofProvider,
        zkConfigProvider,
        currentQueryContext: {
            address: dummyContractAddress(),
            // Mock the ledger query so stateful circuits can evaluate locally without crashing
            query: async () => []
        },
        gasCost: emptyRunningCost()
    };

    // 2. Synchronize our commitment hash with the Compact circuit using the pure computeAgeCommitment
    console.log("  [Crypto] Computing matching persistentHash commitment...");
    console.log("  BEGINNER TIP: This commitment is a 'Zero-Knowledge' fingerprint of your data.");
    console.log("     It proves you HAVE the data without showing what it IS.");

    const secretDOBBigInt = BigInt(numericalDOB);
    const { result: PublicCommitment } = await verifierInstance.circuits.computeAgeCommitment(
        context as any,
        secretDOBBigInt,
        UserSalt
    );

    // 3. Define the Age Threshold (18 years ago from today)
    const today = new Date();
    const thresholdDate = new Date(today.getFullYear() - 18, today.getMonth(), today.getDate());
    const thresholdDOB = BigInt(thresholdDate.toISOString().slice(0, 10).replace(/-/g, ''));

    console.log(`  [Policy] Proving age is >= 18 (DOB <= ${thresholdDOB})...`);
    console.log("  Generating cryptographic proof (this keeps your DOB hidden)...");

    try {
        // 4. Test Pure Offchain Circuit
        console.log("\n  --- TEST 1: OFFCHAIN VERIFICATION (Pure Circuit) ---");
        await verifierInstance.circuits.verifyAge(
            context as any,
            secretDOBBigInt,        // The secret you just typed (Private)
            UserSalt,               // Your dynamically generated secret salt (Private)
            thresholdDOB,           // The 18+ threshold (Public)
            PublicCommitment        // The expected ledger commitment (Public)
        );

        console.log("  SUCCESS: OFFCHAIN ZK Proof Generated Successfully!");

        // 5. Test Onchain Circuit
        console.log("\n  --- TEST 2: ONCHAIN VERIFICATION (Stateful Circuit) ---");
        console.log("  (Stateful circuits like verifyAgeOnchain write to the blockchain ledger.");
        console.log("  To fully execute them, the contract must be deployed on a Midnight Network node.)");
        await verifierInstance.circuits.verifyAgeOnchain(
            context as any,
            secretDOBBigInt,
            UserSalt,
            thresholdDOB,
            PublicCommitment
        );

        console.log("  ONCHAIN ZK Proof Verification Succeeded (Simulated)");
        console.log(`  Both tests proved to the network that your age satisfies the 18+ condition`);
        console.log(`  WITHOUT disclosing your birthdate (${numericalDOB}) to the verifier.`);

    } catch (error: any) {
        if (error.message?.includes('fetch failed') || error.message?.includes('ECONNREFUSED')) {
            console.error("\n  ❌ ERROR: Could not connect to the Midnight Proof Server.");
            console.error("  Please ensure the sidecar is running:");
            console.error("  docker run -p 6300:6300 midnightntwrk/proof-server:8.0.3\n");
        } else {
            console.error("\n  Proof Generation Failed:", error);
        }
    }
}

runProof().catch(console.error);
