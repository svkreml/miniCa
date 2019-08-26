import { GostUtils, Hex } from './gost-utils';

describe('GostUtils', () => {
  it('should create an instance', () => {
    expect(new GostUtils()).toBeTruthy();
  });

/*
  it('test Hex encode', () => {
       let abcdefg = Hex.decode('61626364656667', undefined);
       let nu = Hex.encode('abcdefg', undefined);

       expect(nu === '61626364656667').toBeTruthy();
    });

  it('test Hex decode', () => {
        expect(new GostUtils()).toBeTruthy();
    });*/
});
