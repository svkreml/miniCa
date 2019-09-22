import {AlgorithmIdentifier} from 'x509-ts';
import {DERElement, ObjectIdentifier} from 'asn1-ts';

export class Alg {

    code: string;
    title: string;
    subtleParams: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams;
    signatureOid: AlgorithmIdentifier;

    constructor(code: string, title: string, subtleParams: any, signatureOid: AlgorithmIdentifier) {
        this.code = code;
        this.title = title;
        this.subtleParams = subtleParams;
        this.signatureOid = signatureOid;
    }

    // tslint:disable-next-line:variable-name
   private static _algs;

    public static get algs(): Map<string, Alg> {
        if (this._algs) {
            return this._algs;
        }

        this._algs = new Map<string, Alg>();


        this._algs.set('RSA-4096-SHA-1', new Alg('RSA-4096-SHA-1', 'RSA-4096-SHA-1', {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-1'
            },
            new AlgorithmIdentifier(
                new ObjectIdentifier([1, 2, 840, 113549, 1, 1, 5]),
                new DERElement(),
            )));
        this._algs.set('RSA-4096-SHA-256', new Alg('RSA-4096-SHA-256', 'RSA-4096-SHA-256', {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            new AlgorithmIdentifier(
                new ObjectIdentifier([1, 2, 840, 113549, 1, 1, 11]),
                new DERElement(),
            )));
        this._algs.set('RSA-2048-SHA-256', new Alg('RSA-2048-SHA-256', 'RSA-2048-SHA-256', {
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

        // _algs.push(new Alg('TC-256', 'Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider'));
        // _algs.push(new Alg('TC-512', 'Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider'));
        // _algs.push(new Alg('CP-01', 'Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider'));
        // _algs.push(new Alg('SC-01', 'Signal-COM ECGOST Cryptographic Provider'));
        // _algs.push(new Alg('ECDSA-25', 'Microsoft Base DSS and Diffie-Hellman Cryptographic Provider'));
        return this._algs;
    }

    static findAlgBySubtleParams(subtleParams: any): Alg {
        let a;
        this.algs.forEach((v: Alg, k: string) => {
            if (subtleParams.name && v.subtleParams.name === subtleParams.name &&
                subtleParams.hash && v.subtleParams.hash && v.subtleParams.hash === subtleParams.hash.name &&
                subtleParams.modulusLength && v.subtleParams.modulusLength && v.subtleParams.modulusLength === subtleParams.modulusLength)
                a = v;
        });
        return a;
    }
}
