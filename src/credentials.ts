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
 * Note: In a production ZK system, the commitment would be generated using a 
 * SNARK-friendly hash like Poseidon or persistentHash.
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
  date: string
): Credential {
  const salt = randomBytes(32).toString('hex');
  
  // Commitment that the user is "accredited"
  const status = 1; // 1 for ACTIVE/Accredited
  const statusBuffer = Buffer.alloc(32);
  statusBuffer.writeUInt8(status, 31);

  const saltBuffer = Buffer.from(salt, 'hex');
  const commitment = createHash('sha256')
    .update(Buffer.concat([statusBuffer, saltBuffer]))
    .digest('hex');

  return {
    id: `vc:investor:${randomBytes(8).toString('hex')}`,
    type: ['VerifiableCredential', 'InvestorCredential'],
    issuer: issuer.did,
    holder: holderDid,
    issuanceDate: new Date().toISOString(),
    claims: {
      status: 'accredited',
      accreditationDate: date
    },
    commitment,
    salt
  };
}
