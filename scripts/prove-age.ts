import { 
  NodeZkConfigProvider 
} from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { 
  httpClientProofProvider 
} from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { 
  dummyContractAddress,
  emptyRunningCost
} from '@midnight-ntwrk/compact-runtime';
import { Contract } from '../contracts/managed/verifier/contract/index.js';
import * as path from 'path';

/**
 * SELECTIVE DISCLOSURE PROOF DEMO
 * alice generates a ZK proof that her birth date matches an identity check.
 */

async function runProof() {
    console.log("--- Starting Selective Disclosure Proof Generation ---");

    const AliceDOB = 19900101n;
    const AliceSalt = new Uint8Array(32).fill(1);
    const AliceCommitment = new Uint8Array(32); 
    
    // 1. Initialize Providers
    const zkConfigProvider = new NodeZkConfigProvider(
        path.resolve('contracts/managed/verifier/compiler')
    );
    const proofProvider = httpClientProofProvider(
        'http://localhost:6300',
        zkConfigProvider
    );

    // 2. Initialize Contract Instance (no witnesses needed for pure circuits)
    const verifierInstance = new Contract({});

    console.log("Generating Zero-Knowledge Proof via Proof Server...");
    
    try {
        // Pure circuits just need a context with the providers
        const context = {
            proofProvider,
            zkConfigProvider,
            currentQueryContext: {
                address: dummyContractAddress(),
            },
            gasCost: emptyRunningCost()
        };

        // Pure circuit 'verifyAge' expects: context, secret_dob, secret_salt, expected_dob, expected_commitment
        await verifierInstance.circuits.verifyAge(
            context as any,
            AliceDOB,
            AliceSalt,
            AliceDOB, // Alice matches her own claim
            AliceCommitment
        );

        console.log("✅ ZK Proof Generated Successfully!");
        console.log("The Proof Server processed the pure circuit AliceDOB == ClaimedDOB.");

    } catch (error) {
        console.error("❌ Proof Generation Failed:", error);
    }
}

runProof().catch(console.error);
