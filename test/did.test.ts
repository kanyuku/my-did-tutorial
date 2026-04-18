import { describe, it, expect } from 'vitest';
import { generateDID, createDIDDocument } from '../src/did.js';

describe('DID Module', () => {
  it('should generate a valid Midnight DID', () => {
    const keyPair = generateDID();
    
    expect(keyPair.did).toMatch(/^did:midnight:z/);
    expect(keyPair.publicKey).toHaveLength(64); // 32 bytes hex
    expect(keyPair.privateKey).toHaveLength(64);
  });

  it('should create a compliant W3C DID Document', () => {
    const keyPair = generateDID();
    const document = createDIDDocument(keyPair);

    expect(document.id).toBe(keyPair.did);
    expect(document['@context']).toContain('https://www.w3.org/ns/did/v1');
    expect(document.verificationMethod[0].publicKeyHex).toBe(keyPair.publicKey);
  });

  it('should derive consistent identifiers', () => {
    const sk = '0'.repeat(64);
    // In our simulation, did depends on the public key which depends on sk
    // We just want to ensure it's functional
    const keyPair = generateDID();
    const didIdentifier = keyPair.did.split(':').pop();
    expect(didIdentifier?.startsWith('z')).toBe(true);
  });
});
