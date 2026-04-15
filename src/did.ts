import { createHash, randomBytes } from 'crypto';

const DID_METHOD = 'midnight';

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

export function generateDID(): DIDKeyPair {
  const privateKeyBytes = randomBytes(32);
  const privateKey = privateKeyBytes.toString('hex');
  
  // Use the Compact-compatible derivation
  const publicKey = deriveCompactPk(privateKey);

  const didIdentifier = `z${publicKey.slice(0, 44)}`;
  const did = `did:${DID_METHOD}:${didIdentifier}`;

  return { did, publicKey, privateKey };
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
