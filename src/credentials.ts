import { DIDKeyPair } from './did.js';
import { createHash, randomBytes } from 'crypto';

export interface Credential {
  id: string;
  type: string[];
  issuer: string;
  holder: string;
  issuanceDate: string;
  claims: any;
  commitment: string;
  salt: string;
}

/**
 * Issues an Age Credential for a holder.
 * 
 * IMPORTANT: In this tutorial, the commitment in the credential object uses SHA256 
 * for simplicity. However, the Midnight ZK circuits use 'persistentHash' (Poseidon).
 * The `scripts/prove-age.ts` handles this by re-computing the correct SNARK-friendly 
 * commitment during proof generation.
 */
export function issueAgeCredential(
  issuer: DIDKeyPair,
  holderDid: string,
  dob: string,
  threshold: number
): Credential {
  const salt = randomBytes(32).toString('hex');
  
  // Create a commitment of the private data (DOB + salt)
  const dobNum = parseInt(dob.replace(/-/g, '')); // YYYYMMDD
  const dobBuffer = Buffer.alloc(32);
  dobBuffer.writeUInt32BE(dobNum, 28); // Standard Field padding

  const saltBuffer = Buffer.from(salt, 'hex');
  const commitment = createHash('sha256')
    .update(Buffer.concat([dobBuffer, saltBuffer]))
    .digest('hex');

  return {
    id: `vc:age:${randomBytes(8).toString('hex')}`,
    type: ['VerifiableCredential', 'AgeCredential'],
    issuer: issuer.did,
    holder: holderDid,
    issuanceDate: new Date().toISOString(),
    claims: {
      dateOfBirth: dob,
      ageThreshold: threshold
    },
    commitment,
    salt
  };
}

/**
 * Issues an Accredited Investor Credential.
 */
export function issueInvestorCredential(
  issuer: DIDKeyPair,
  holderDid: string,
  date: string,
  netWorth: number
): Credential {
  const salt = randomBytes(32).toString('hex');
  
  // Numerical Net Worth tracking
  const netWorthBuffer = Buffer.alloc(32);
  netWorthBuffer.writeBigUInt64BE(BigInt(netWorth), 24); // 8 bytes for Uint64 at the end of 32 bytes

  const saltBuffer = Buffer.from(salt, 'hex');
  const commitment = createHash('sha256')
    .update(Buffer.concat([netWorthBuffer, saltBuffer]))
    .digest('hex');

  return {
    id: `vc:investor:${randomBytes(8).toString('hex')}`,
    type: ['VerifiableCredential', 'InvestorCredential'],
    issuer: issuer.did,
    holder: holderDid,
    issuanceDate: new Date().toISOString(),
    claims: {
      status: 'accredited',
      accreditationDate: date,
      netWorth
    },
    commitment,
    salt
  };
}
