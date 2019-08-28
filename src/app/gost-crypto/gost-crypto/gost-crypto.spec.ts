import { GostCrypto } from './gost-crypto';

describe('GostCrypto', () => {
  it('should create an instance', () => {
    expect(new GostCrypto()).toBeTruthy();
  });
});
