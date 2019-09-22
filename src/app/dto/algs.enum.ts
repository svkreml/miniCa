import {AlgorithmIdentifier} from 'x509-ts';
import {DERElement, ObjectIdentifier} from 'asn1-ts';

export class Alg {

    code: string;
    title: string;
    subtleParams: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams;
    signatureOid: AlgorithmIdentifier;
   static algs;

    constructor(code: string, title: string, subtleParams: any, signatureOid: AlgorithmIdentifier) {
        this.code = code;
        this.title = title;
        this.subtleParams = subtleParams;
        this.signatureOid = signatureOid;
    }



    public static getAlgs(): Map<string, Alg> {
        if (this.algs) return this.algs;

        this.algs = new Map<string, Alg>();


        this.algs.set('RSA-4096-SHA-256', new Alg('RSA-4096', 'RSA-4096', {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            new AlgorithmIdentifier(
                new ObjectIdentifier([1, 2, 840, 113549, 1, 1, 11]),
                new DERElement(),
            )));
        this.algs.set('RSA-2048-SHA-256', new Alg('RSA-2048', 'RSA-2048', {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            new AlgorithmIdentifier(
                new ObjectIdentifier([1, 2, 840, 113549, 1, 1, 11]),
                new DERElement(),
            )
        ));


        // algs.push(new Alg('TC-256', 'Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider'));
        // algs.push(new Alg('TC-512', 'Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider'));
        // algs.push(new Alg('CP-01', 'Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider'));
        // algs.push(new Alg('SC-01', 'Signal-COM ECGOST Cryptographic Provider'));
        // algs.push(new Alg('ECDSA-25', 'Microsoft Base DSS and Diffie-Hellman Cryptographic Provider'));
        return this.algs;
    }
}
