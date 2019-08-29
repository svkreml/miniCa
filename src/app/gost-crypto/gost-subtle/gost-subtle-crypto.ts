import {AlgorithmDto} from '../../dto/algorithm-dto';
import {GostEngine} from '../gost-engine/gost-engine';
import {GostCrypto} from '../gost-crypto/gost-crypto';

export class GostSubtleCrypto implements SubtleCrypto {

    subtle: SubtleCrypto = new SubtleCrypto();

    constructor(private gostCrypto: GostCrypto, private gostEngine: GostEngine) {
    }

    checkNative(algorithm: AlgorithmDto) {
        if (!this.subtle || !algorithm) {
            return false;
        }
        // Prepare name
        let name;
        if (typeof algorithm === 'string' || algorithm instanceof String) {
            name = algorithm;
        } else {
            algorithm.name;
        }
        if (!name) {
            return false;
        }
        name = name.toUpperCase();
        // Digest algorithm for key derivation
        if ((name.indexOf('KDF') >= 0 || name.indexOf('HMAC') >= 0) && algorithm.hash) {
            return this.checkNative(algorithm.hash as AlgorithmDto);
        }
        // True if no supported names
        return name.indexOf('GOST') === -1 &&
            name.indexOf('SHA-1') === -1 &&
            name.indexOf('RC2') === -1 &&
            name.indexOf('?DES') === -1;
    }

    deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        throw new Error('Method not implemented.');
    }

    deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | ConcatParams | HkdfCtrParams | Pbkdf2Params | AesDerivedKeyParams | HmacImportParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        throw new Error('Method not implemented.');
    }

    // exportKey(format: 'jwk', key: CryptoKey): PromiseLike<JsonWebKey>;
    // exportKey(format: 'raw' | 'pkcs8' | 'spki', key: CryptoKey): PromiseLike<ArrayBuffer>;

    digest(algorithm: string | Algorithm, data: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView): PromiseLike<ArrayBuffer> {
        throw new Error('Method not implemented.');
    }

    // generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair>;
    // generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;

    // exportKey(format: string, key: CryptoKey): PromiseLike<ArrayBuffer | JsonWebKey>;
    exportKey(format: any, key: any): PromiseLike<any> {
        throw new Error('Method not implemented.');
    }

    // importKey(format: 'jwk', keyData: JsonWebKey, algorithm: string | HmacImportParams | RsaHashedImportParams | EcKeyImportParams | DhImportKeyParams | AesKeyAlgorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    // importKey(format: 'raw' | 'pkcs8' | 'spki', keyData: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView, algorithm: string | HmacImportParams | RsaHashedImportParams | EcKeyImportParams | DhImportKeyParams | AesKeyAlgorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;

    // generateKey(algorithm: Pbkdf2Params | AesKeyGenParams | HmacKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    generateKey(algorithm: any, extractable: any, keyUsages: any): PromiseLike<any> {
        throw new Error('Method not implemented.');
    }

    // importKey(format: string, keyData: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | JsonWebKey, algorithm: string | HmacImportParams | RsaHashedImportParams | EcKeyImportParams | DhImportKeyParams | AesKeyAlgorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    importKey(format: any, keyData: any, algorithm: any, extractable: any, keyUsages: any): PromiseLike<any> {
        throw new Error('Method not implemented.');
    }

    unwrapKey(format: string, wrappedKey: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView, unwrappingKey: CryptoKey, unwrapAlgorithm: string | Algorithm, unwrappedKeyAlgorithm: string | Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        throw new Error('Method not implemented.');
    }

    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: string | Algorithm): PromiseLike<ArrayBuffer> {
        throw new Error('Method not implemented.');
    }

    encrypt(algorithm, key, data): PromiseLike<any> {

        if (this.checkNative(algorithm)) {
            return this.subtle.encrypt(algorithm, key, data);
        }

        algorithm = this.gostCrypto.normalize(algorithm, 'encrypt');
        return new Promise((resolve, reject) => {
            if (this.gostEngine) {
                resolve(this.gostEngine.execute(algorithm, 'encrypt',
                    [this.gostCrypto.extractKey('encrypt', algorithm, key), data]));
            } else {
                reject(new Error('gostEngine not found'));
            }
        });


    }

    decrypt(algorithm, key, data): PromiseLike<any> {
        if (this.checkNative(algorithm)) {
            return this.subtle.decrypt(algorithm, key, data);
        }
        algorithm = this.gostCrypto.normalize(algorithm, 'decrypt');
        return new Promise((resolve, reject) => {
            if (this.gostEngine) {
                resolve(this.gostEngine.execute(algorithm, 'decrypt',
                    [this.gostCrypto.extractKey('decrypt', algorithm, key), data]));
            } else {
                reject(new Error('gostEngine not found'));
            }
        });
    }

    sign(algorithm, key, data): PromiseLike<any> {
        if (this.checkNative(algorithm)) {
            return this.subtle.sign(algorithm, key, data);
        }
        algorithm = this.gostCrypto.normalize(algorithm, 'sign');
        return new Promise((resolve, reject) => {
            if (this.gostEngine) {
                resolve(this.gostEngine.execute(algorithm, 'sign', [this.gostCrypto.extractKey('sign', algorithm, key), data]).then((data) => {
                    if (algorithm.procreator === 'SC' && algorithm.mode === 'SIGN') {
                        data = this.gostCrypto.asn1.GostSignature.encode(data);
                    }
                    return data;
                }));
            } else {
                reject(new Error('gostEngine not found'));
            }
        });
    }

    verify(algorithm, key, signature, data): PromiseLike<any> {
        if (this.checkNative(algorithm)) {
            return this.subtle.verify(algorithm, key, signature, data);
        }
        /*    {
        return new Promise(call).then(function () {
            if (checkNative(algorithm))
                return rootCrypto.subtle.verify(algorithm, key, signature, data);

            algorithm = normalize(algorithm, 'verify');
            if (algorithm.procreator === 'SC' && algorithm.mode === 'SIGN') {
                var obj = gostCrypto.asn1.GostSignature.decode(signature);
                signature = {r: obj.r, s: obj.s};
            }
            return execute(algorithm, 'verify',
                    [extractKey('verify', algorithm, key), signature, data]);
        });*/
    }

    //  digest
    //  generateKey
}
