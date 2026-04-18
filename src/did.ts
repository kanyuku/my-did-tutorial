import { createHash, randomBytes } from 'crypto';

const DID_METHOD = 'midnight';

/**
 * PRIVACY GUARANTEE:
 * DIDs in Midnight are based on public keys derived from local secrets. 
 * Only the Public Key and the multibase identifier are ever shared on-chain.
 * Your private signing key never leaves your local environment.
 */

export interface DIDKeyPair {
  did: string;
  publicKey: string;
  privateKey: string;
}

/**
 * Simulates the Compact derive_pk logic.
 * In a real DApp, this would use persistentHash from the Midnight SDK.
 */
function deriveCompactPk(privateKeyHex: string): string {
  const prefix = Buffer.alloc(32);
  prefix.write("midnight:pk:", 0, "utf8"); // 12 bytes + 20 zeros

  const sk = Buffer.from(privateKeyHex, 'hex');

  // Simulation of persistentHash using sha256 for this demo
  return createHash('sha256')
    .update(Buffer.concat([prefix, sk]))
    .digest('hex');
}

/**
 * Generates a new Midnight DID using a private key (signing key).
 * 
 * Cryptographic logic:
 * 1. Generates 32 bytes of randomness for the private key.
 * 2. Derives a Public Key using a deterministic hash function (simulating Poseidon).
 * 3. Formats the identifier using 'z' prefix (multibase) for W3C alignment.
 * 
 * @returns {DIDKeyPair} The generated keys and compliant DID string.
 */
export function generateDID(): DIDKeyPair {
  const privateKeyBytes = randomBytes(32);
  const privateKey = privateKeyBytes.toString('hex');

  // Use the Compact-compatible derivation
  // In a real Midnight circuit, this is done via persistentHash
  const publicKey = deriveCompactPk(privateKey);

  // W3C DID Standard: did:<method>:<identifier>
  // identifier prefix 'z' indicates multibase (typically base58btc for public keys)
  const didIdentifier = `z${publicKey.slice(0, 44)}`;
  const did = `did:${DID_METHOD}:${didIdentifier}`;

  return { did, publicKey, privateKey };
}

export interface DIDDocument {
  '@context': string[];
  id: string;
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyHex: string;
  }>;
  authentication: string[];
  assertionMethod: string[];
}

export function createDIDDocument(keyPair: DIDKeyPair): DIDDocument {
  const keyId = `${keyPair.did}#keys-1`;

  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1'
    ],
    id: keyPair.did,
    verificationMethod: [{
      id: keyId,
      type: 'Ed25519VerificationKey2020',
      controller: keyPair.did,
      publicKeyHex: keyPair.publicKey
    }],
    authentication: [keyId],
    assertionMethod: [keyId]
  };
}
