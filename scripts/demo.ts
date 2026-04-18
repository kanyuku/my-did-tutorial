import { generateDID, createDIDDocument } from '../src/did.js';
import { issueAgeCredential, issueInvestorCredential } from '../src/credentials.js';

async function main() {
  console.log("Starting Midnight DID Beginner Project\n");

  // Step 1: Create DIDs
  const issuer = generateDID();   // KYC Provider
  const holder = generateDID();   // Alice (the user)

  console.log("Issuer DID:", issuer.did);
  console.log("Holder (Alice) DID:", holder.did);

  // Step 2: Create DID Document for issuer
  const issuerDocument = createDIDDocument(issuer);
  console.log("\nIssuer DID Document created successfully!");
  console.log(JSON.stringify(issuerDocument, null, 2));

  // Step 3: Issue credentials
  const ageCredential = issueAgeCredential(
    issuer,
    holder.did,
    '1998-03-15',  // Private data - stays with Alice
    18
  );

  const investorCredential = issueInvestorCredential(
    issuer,
    holder.did,
    '2024-01-10',
    1500000 // Added net worth value
  );

  console.log("\nAge Credential Issued (over 18)");
  console.log("Credential Commitment:", ageCredential.commitment);
  
  console.log("\nAccredited Investor Credential Issued");
  console.log("Credential Commitment:", investorCredential.commitment);

  console.log("\n=== Contract Mapping ===");
  console.log("• Issuer DID Registration -> [did-registry.compact]");
  console.log("  Circuit: registerDID (discloses doc commitment and pk)");
  
  console.log("\n• Age Credential Issuance -> [credential-issuer.compact]");
  console.log("  Circuit: issueCredential (discloses holder_did_hash and commitment)");

  console.log("\n• Selective Disclosure -> [verifier.compact]");
  console.log("  Circuit: verifyAge (proves DOB >= 18 using DOB and salt witnesses)");

  console.log("\n=== Privacy Summary ===");
  console.log("• Alice's exact date of birth stays private (witness data)");
  console.log("• Only zero-knowledge proofs will be shared with the network");
  console.log("• No personal data ever touches the on-chain ledger");
}

main().catch(console.error);
