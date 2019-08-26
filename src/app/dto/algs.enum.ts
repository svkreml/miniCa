export class Alg {

  constructor(code: string, title: string) {
    this.code = code;
    this.title = title;
  }

  code: string;
  title: string;

  public static getAlgs(): Alg[] {
    const algs = [];
    algs.push(new Alg('TC-256', 'Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider'));
    algs.push(new Alg('TC-512', 'Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider'));
    algs.push(new Alg('CP-01', 'Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider'));
    algs.push(new Alg('SC-01', 'Signal-COM ECGOST Cryptographic Provider'));
    algs.push(new Alg('RSA-2048', 'Microsoft Strong Cryptographic Provider'));
    algs.push(new Alg('ECDSA-25', 'Microsoft Base DSS and Diffie-Hellman Cryptographic Provider'));
    return algs;
  }
}
