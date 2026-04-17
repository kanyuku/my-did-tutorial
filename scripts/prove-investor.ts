import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { dummyContractAddress, emptyRunningCost } from '@midnight-ntwrk/compact-runtime';
import { Contract } from '../contracts/managed/verifier/contract/index.js';
import * as path from 'path';

/**
 * SELECTIVE DISCLOSURE PROOF DEMO
 * alice generates a ZK proof that she is an accredited investor 
 * without revealing her actual net worth.
 */

async function runProof() {
    console.log("--- Starting Selective Disclosure Proof Generation (Accreditation) ---");

    const IsAccredited = 1n; // 1 means true/accredited
    const AliceCommitment = new Uint8Array(32); 
    
    // 1. Initialize Providers
    const zkConfigProvider = new NodeZkConfigProvider(
        path.resolve('contracts/managed/verifier/compiler')
    );
    const proofProvider = httpClientProofProvider(
        'http://localhost:6300',
        zkConfigProvider
    );

    // 2. Initialize Contract Instance
    const verifierInstance = new Contract({});

    console.log("Generating Zero-Knowledge Proof via Proof Server...");
    
    try {
        const context = {
            proofProvider,
            zkConfigProvider,
            currentQueryContext: {
                address: dummyContractAddress(),
            },
            gasCost: emptyRunningCost()
        };

        // Pure circuit 'verifyAccredited' expects: context, status, expected_commitment
        await verifierInstance.circuits.verifyAccredited(
            context as any,
            IsAccredited,
            AliceCommitment
        );

        console.log("✅ ZK Proof Generated Successfully!");
        console.log("The Proof Server processed the pure circuit IsAccredited == 1.");

    } catch (error) {
        console.error("❌ Proof Generation Failed:", error);
    }
}

runProof().catch(console.error);
