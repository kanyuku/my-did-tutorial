import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { dummyContractAddress, emptyRunningCost } from '@midnight-ntwrk/compact-runtime';
import { Contract } from '../contracts/managed/verifier/contract/index.js';
import * as path from 'path';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { generateDID } from '../src/did.js';
import { issueInvestorCredential } from '../src/credentials.js';

/**
 * SELECTIVE DISCLOSURE PROOF DEMO (Interactive)
 * Alice generates a ZK proof that she is an accredited investor 
 * (Net Worth >= $1,000,000) without revealing her actual net worth.
 * 
 * PRIVACY GUARANTEE:
 * Your actual financial data (Net Worth) never leaves your device.
 * The proof only confirms you meet the threshold.
 */

async function runProof() {
    console.log("╔══════════════════════════════════════════════╗");
    console.log("║    Interactive Investor ZK Proof Demo        ║");
    console.log("╚══════════════════════════════════════════════╝\n");

    const rl = createInterface({ input: stdin, output: stdout });
    const netWorthInput = await rl.question('  Enter your secret Net Worth (USD): ');
    rl.close();

    const numericalNetWorth = BigInt(netWorthInput.trim());
    const Threshold = 1000000n; // $1,000,000 USD
    
    console.log(`\n  [Local Storage] Secret Net Worth recorded as: $${numericalNetWorth.toLocaleString()}`);

    // 1. Initialize Providers
    const zkConfigProvider = new NodeZkConfigProvider(
        path.resolve('contracts/managed/verifier/compiler')
    );
    const proofProvider = httpClientProofProvider(
        'http://localhost:6300',
        zkConfigProvider
    );

    const verifierInstance = new Contract({});

    // 2. Issue a dynamic credential to get a real salt
    console.log("  [DApp] Issuing an Investor VC to Alice...");
    const issuer = generateDID();
    const holder = generateDID();
    const credential = issueInvestorCredential(issuer, holder.did, new Date().toISOString(), Number(numericalNetWorth));
    
    const UserSalt = new Uint8Array(Buffer.from(credential.salt, 'hex'));

    try {
        const context = {
            proofProvider,
            zkConfigProvider,
            currentQueryContext: {
                address: dummyContractAddress(),
                query: async () => [] 
            },
            gasCost: emptyRunningCost()
        };

        // 3. Compute matching persistentHash commitment
        console.log("  [Crypto] Computing matching persistentHash commitment...");
        const { result: PublicCommitment } = await verifierInstance.circuits.computeInvestorCommitment(
            context as any,
            numericalNetWorth,
            UserSalt
        );

        console.log(`  [Policy] Proving Net Worth is >= $${Threshold.toLocaleString()}...`);
        console.log("  Generating cryptographic proof (this keeps your Net Worth hidden)...");

        // 4. Verify Accreditation (Pure Circuit)
        await verifierInstance.circuits.verifyAccredited(
            context as any,
            numericalNetWorth,    // Private
            UserSalt,             // Private
            Threshold,            // Public
            PublicCommitment      // Public
        );

        console.log("\n  SUCCESS: ZK Proof Generated Successfully!");
        console.log(`  You have proved to the verifier that you meet the $${Threshold.toLocaleString()} threshold`);
        console.log(`  WITHOUT disclosing your actual net worth ($${numericalNetWorth.toLocaleString()}).`);

    } catch (error: any) {
        if (error.message?.includes('fetch failed') || error.message?.includes('ECONNREFUSED')) {
            console.error("\n  ❌ ERROR: Could not connect to the Midnight Proof Server.");
            console.error("  Please ensure the sidecar is running:");
            console.error("  docker run -p 6300:6300 midnightntwrk/proof-server:8.0.3\n");
        } else {
            console.error("\n  ERROR: Proof Generation Failed:", error);
        }
    }
}

runProof().catch(console.error);
