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
 * PRIVACY GUARANTEE:
 * 1. Data Minimization: We only commit a hash of the data to the ledger.
 * 2. Unlinkability: Each credential uses a unique high-entropy 'salt'. 
 *    Even if two credentials contain the same data (same DOB), their 
 *    commitments will look completely unrelated on-chain.
 */

/**
 * Issues an Age Credential for a holder.
 * 
 * Cryptographic logic (Commitment Scheme):
 * 1. Generates a 32-byte high-entropy salt.
 * 2. Formats the private Date of Birth (DOB) into a ZK-friendly numerical format.
 * 3. Creates a 'commitment' = Hash(PrivateData || Salt).
 * 
 * This commitment is shared on-chain. When proving age, the holder provides the 
 * original DOB and salt as secret witnesses to the ZK circuit. The circuit 
 * re-computes the hash and verifies it matches the on-chain commitment without 
 * revealing the DOB.
 * 
 * IMPORTANT: This simulation uses SHA256. The actual Midnight circuits use 
 * Poseidon ('persistentHash') for efficiency within the SNARK.
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

/**
 * Issues a KYC Credential.
 */
export function issueKYCCredential(
  issuer: DIDKeyPair,
  holderDid: string,
  countryCode: string,
  expiryDate: number,
  idNumber: string
): Credential {
  const salt = randomBytes(32).toString('hex');
  const idHash = createHash('sha256').update(idNumber).digest('hex');
  
  // Numerical/Byte tracking for commitment (mimicking Compact logic)
  const countryBuffer = Buffer.alloc(32);
  countryBuffer.write(countryCode, 0); // "US" -> [85, 83, 0...0]

  const expiryBuffer = Buffer.alloc(32);
  expiryBuffer.writeBigUInt64BE(BigInt(expiryDate), 24);

  const idHashBuffer = Buffer.from(idHash, 'hex');
  const saltBuffer = Buffer.from(salt, 'hex');

  const commitment = createHash('sha256')
    .update(Buffer.concat([countryBuffer, expiryBuffer, idHashBuffer, saltBuffer]))
    .digest('hex');

  return {
    id: `vc:kyc:${randomBytes(8).toString('hex')}`,
    type: ['VerifiableCredential', 'KYCCredential'],
    issuer: issuer.did,
    holder: holderDid,
    issuanceDate: new Date().toISOString(),
    claims: {
      countryCode,
      expiryDate,
      idHash
    },
    commitment,
    salt
  };
}
