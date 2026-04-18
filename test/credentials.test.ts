import { describe, it, expect } from 'vitest';
import { generateDID } from '../src/did.js';
import { issueAgeCredential, issueInvestorCredential } from '../src/credentials.js';

describe('Credentials Module', () => {
  const issuer = generateDID();
  const holderDid = 'did:midnight:test-holder';

  it('should issue an age credential with a valid commitment', () => {
    const cred = issueAgeCredential(issuer, holderDid, '2000-01-01', 18);
    
    expect(cred.type).toContain('AgeCredential');
    expect(cred.holder).toBe(holderDid);
    expect(cred.commitment).toHaveLength(64);
    expect(cred.salt).toHaveLength(64);
  });

  it('should issue an investor credential with a valid commitment', () => {
    const cred = issueInvestorCredential(issuer, holderDid, '2023-05-01', 1000000);
    
    expect(cred.type).toContain('InvestorCredential');
    expect(cred.claims.netWorth).toBe(1000000);
  });

  it('should generate different commitments for different salts', () => {
    const cred1 = issueAgeCredential(issuer, holderDid, '2000-01-01', 18);
    const cred2 = issueAgeCredential(issuer, holderDid, '2000-01-01', 18);
    
    expect(cred1.commitment).not.toBe(cred2.commitment);
  });
});
