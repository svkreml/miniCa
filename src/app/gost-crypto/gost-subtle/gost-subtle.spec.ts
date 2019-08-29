import { GostSubtleCrypto } from './gost-subtle-crypto';

describe('GostSubtle', () => {
  it('should create an instance', () => {
    expect(new GostSubtleCrypto()).toBeTruthy();
  });
});
