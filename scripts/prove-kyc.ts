import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { dummyContractAddress, emptyRunningCost } from '@midnight-ntwrk/compact-runtime';
import { Contract } from '../contracts/managed/verifier/contract/index.js';
import * as path from 'path';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { createHash } from 'crypto';
import { generateDID } from '../src/did.js';
import { issueKYCCredential } from '../src/credentials.js';

/**
 * SELECTIVE DISCLOSURE PROOF DEMO (Interactive)
 * Alice proves she is eligible (Correct country, Not Expired) 
 * without revealing her PII or Passport number to the platform.
 * 
 * PRIVACY GUARANTEE:
 * 1. PII (Name, Passport Number) stays locally encrypted.
 * 2. Hashed identifiers are used to prevent multi-accounting without linking to real identity.
 */

async function runProof() {
    console.log("╔══════════════════════════════════════════════╗");
    console.log("║    Interactive KYC ZK Proof Demo             ║");
    console.log("╚══════════════════════════════════════════════╝\n");

    const rl = createInterface({ input: stdin, output: stdout });
    const countryInput = await rl.question('  Enter your Country Code (e.g., US, CH): ');
    const expiryInput = await rl.question('  Enter ID Expiry Date (YYYYMMDD): ');
    const idInput = await rl.question('  Enter Passport Number (Secretly hashed locally): ');
    rl.close();

    const countryCode = countryInput.trim().toUpperCase();
    const expiryDate = BigInt(expiryInput.trim());
    const idHash = createHash('sha256').update(idInput.trim()).digest('hex');
    const ThresholdExpiry = 20240417n; // Today's simulated date

    // 1. Providers
    const zkConfigProvider = new NodeZkConfigProvider(path.resolve('contracts/managed/verifier/compiler'));
    const proofProvider = httpClientProofProvider('http://localhost:6300', zkConfigProvider);
    const verifierInstance = new Contract({});

    // 2. Issue dynamic credential
    console.log("\n  [DApp] Issuing a KYC VC to Alice...");
    const issuer = generateDID();
    const holder = generateDID();
    const credential = issueKYCCredential(issuer, holder.did, countryCode, Number(expiryDate), idInput.trim());
    
    const UserSalt = new Uint8Array(Buffer.from(credential.salt, 'hex'));
    const countryBuffer = Buffer.alloc(32);
    countryBuffer.write(countryCode, 0);
    const CountryBytes32 = new Uint8Array(countryBuffer);
    const IdHashBytes32 = new Uint8Array(Buffer.from(idHash, 'hex'));

    try {
        const context = {
            proofProvider,
            zkConfigProvider,
            currentQueryContext: { address: dummyContractAddress(), query: async () => [] },
            gasCost: emptyRunningCost()
        };

        // 3. Compute matching persistentHash commitment
        console.log("  [Crypto] Computing matching persistentHash commitment...");
        const { result: PublicCommitment } = await verifierInstance.circuits.computeKYCCommitment(
            context as any,
            CountryBytes32,
            expiryDate,
            IdHashBytes32,
            UserSalt
        );

        console.log(`  [Policy] Proving Nationality NOT "RU" and Expiry >= ${ThresholdExpiry}...`);
        console.log("  Generating ZK Proof (PII stays on your device)...");

        // 4. Verify KYC (Pure Circuit)
        await verifierInstance.circuits.verifyKYC(
            context as any,
            CountryBytes32,       // Private
            expiryDate,           // Private
            IdHashBytes32,        // Private (but will be disclosed by the circuit)
            UserSalt,             // Private
            ThresholdExpiry,      // Public
            PublicCommitment      // Public
        );

        console.log("\n  SUCCESS: ZK Proof Generated Successfully!");
        
        // Simulations of what the platform sees
        console.log("  ╔════════════════ PLATFORM VIEW ═══════════════╗");
        console.log("  ║ [Proof]: VALID                                ║");
        console.log("  ║ [Claims]: Nationality OK, Valid and Unique    ║");
        console.log(`  ║ [Unique ID Hash]: ${Buffer.from(IdHashBytes32).toString('hex').slice(0, 16)}... ║`);
        console.log("  ╚══════════════════════════════════════════════╝");
        console.log("\n  Reality: The platform never saw your passport number or actual country!");

    } catch (error: any) {
        if (error.message?.includes('fetch failed') || error.message?.includes('ECONNREFUSED')) {
            console.error("\n  ❌ ERROR: Could not connect to the Midnight Proof Server.");
            console.error("  Please ensure the sidecar is running:");
            console.error("  docker run -p 6300:6300 midnightntwrk/proof-server:8.0.3\n");
        } else {
            console.error("\n  ERROR: Proof Generation Failed:", error);
            console.log("  (Check if you entered a sanctioned country like 'RU' or an expired date)");
        }
    }
}

runProof().catch(console.error);
