import {Key} from '../../dto/key-dto';
import {AlgorithmDto} from '../../dto/algorithm-dto';
import {GostEngine} from '../gost-engine/gost-engine';

export class GostCrypto {
    subtle: SubtleCrypto = new SubtleCrypto();

    constructor() {

    }

    normalize(algorithm/*: anyAlgorithmDto|HashDto | string*/, method: string) {
        if (typeof algorithm === 'string' || algorithm instanceof String) {
            let name = algorithm;
            algorithm = new AlgorithmDto();
            algorithm.name = name as string;
        }
        let name = algorithm.name;
        if (!name) {
            throw new Error('Algorithm name not defined');
        }
        // Extract algorithm modes from name
        let modes = name.split('/');
        modes = modes[0].split('-').concat(modes.slice(1));
        // Normalize the name with default modes
        let na: AlgorithmDto = new AlgorithmDto(); // TODO заменить на класс дто
        name = modes[0].replace(/[\.\s]/g, ''), modes = modes.slice(1);
        if (name.indexOf('28147') >= 0) {
            na = {
                name: 'GOST 28147',
                version: 1989,
                mode: (algorithm.mode || (// ES, MAC, KW
                    (method === 'sign' || method === 'verify') ? 'MAC' :
                        (method === 'wrapKey' || method === 'unwrapKey') ? 'KW' : 'ES')).toUpperCase(),
                length: algorithm.length || 64
            } as AlgorithmDto;
        } else if (name.indexOf('3412') >= 0) {
            na = {
                name: 'GOST R 34.12',
                version: 2015,
                mode: (algorithm.mode || (// ES, MAC, KW
                    (method === 'sign' || method === 'verify') ? 'MAC' :
                        (method === 'wrapKey' || method === 'unwrapKey') ? 'KW' : 'ES')).toUpperCase(),
                length: algorithm.length || 64 // 128
            } as AlgorithmDto;
        } else if (name.indexOf('3411') >= 0) {
            na = {
                name: 'GOST R 34.11',
                version: 2012, // 1994
                mode: (algorithm.mode || (// HASH, KDF, HMAC, PBKDF2, PFXKDF, CPKDF
                    (method === 'deriveKey' || method === 'deriveBits') ? 'KDF' :
                        (method === 'sign' || method === 'verify') ? 'HMAC' : 'HASH')).toUpperCase(),
                length: algorithm.length || 256 // 512
            } as AlgorithmDto;
        } else if (name.indexOf('3410') >= 0) {
            na = {
                name: 'GOST R 34.10',
                version: 2012, // 1994, 2001
                mode: (algorithm.mode || (// SIGN, DH, MASK
                    (method === 'deriveKey' || method === 'deriveBits') ? 'DH' : 'SIGN')).toUpperCase(),
                length: algorithm.length || 256 // 512
            } as AlgorithmDto;
        } else if (name.indexOf('SHA') >= 0) {
            na = {
                name: 'SHA',
                version: (algorithm.length || 160) === 160 ? 1 : 2, // 1, 2
                mode: (algorithm.mode || (// HASH, KDF, HMAC, PBKDF2, PFXKDF
                    (method === 'deriveKey' || method === 'deriveBits') ? 'KDF' :
                        (method === 'sign' || method === 'verify') ? 'HMAC' : 'HASH')).toUpperCase(),
                length: algorithm.length || 160
            } as AlgorithmDto;
        } else if (name.indexOf('RC2') >= 0) {
            na = {
                name: 'RC2',
                version: 1,
                mode: (algorithm.mode || (// ES, MAC, KW
                    (method === 'sign' || method === 'verify') ? 'MAC' :
                        (method === 'wrapKey' || method === 'unwrapKey') ? 'KW' : 'ES')).toUpperCase(),
                length: algorithm.length || 32 // 1 - 1024
            } as AlgorithmDto;
        } else if (name.indexOf('PBKDF2') >= 0) {
            na = this.normalize(algorithm.hash, 'digest');
            na.mode = 'PBKDF2';
        } else if (name.indexOf('PFXKDF') >= 0) {
            na = this.normalize(algorithm.hash, 'digest');
            na.mode = 'PFXKDF';
        } else if (name.indexOf('CPKDF') >= 0) {
            na = this.normalize(algorithm.hash, 'digest');
            na.mode = 'CPKDF';
        } else if (name.indexOf('HMAC') >= 0) {
            na = this.normalize(algorithm.hash, 'digest');
            na.mode = 'HMAC';
        } else {
            throw new Error('Algorithm not supported');
        }

        // Compile modes
        modes.forEach((mode) => {
            mode = mode.toUpperCase();
            if (/^[0-9]+$/.test(mode)) {
                if ((['8', '16', '32'].indexOf(mode) >= 0) || (na.length === 128 && mode === '64')) { // Shift bits
                    if (na.mode === 'ES') {
                        na.shiftBits = parseInt(mode);
                    } else if (na.mode === 'MAC') {
                        na.macLength = parseInt(mode);
                    } else {
                        throw new Error('Algorithm ' + na.name + ' mode ' + mode + ' not supported');
                    }
                } else if (['89', '94', '01', '12', '15', '1989', '1994', '2001', '2012', '2015'].indexOf(mode) >= 0) { // GOST Year
                    let version = parseInt(mode);
                    version = version < 1900 ? (version < 80 ? 2000 + version : 1900 + version) : version;
                    na.version = version;
                } else if (['1'].indexOf(mode) >= 0 && na.name === 'SHA') { // SHA-1
                    na.version = 1;
                    na.length = 160;
                } else if (['256', '384', '512'].indexOf(mode) >= 0 && na.name === 'SHA') { // SHA-2
                    na.version = 2;
                    na.length = parseInt(mode);
                } else if (['40', '128'].indexOf(mode) >= 0 && na.name === 'RC2') { // RC2
                    na.version = 1;
                    na.length = parseInt(mode); // key size
                } else if (['64', '128', '256', '512'].indexOf(mode) >= 0) // block size
                {
                    na.length = parseInt(mode);
                } else if (['1000', '2000'].indexOf(mode) >= 0) // Iterations
                {
                    na.iterations = parseInt(mode);
                }
                // Named Paramsets
            } else if (['E-TEST', 'E-A', 'E-B', 'E-C', 'E-D', 'E-SC', 'E-Z', 'D-TEST', 'D-A', 'D-SC'].indexOf(mode) >= 0) {
                na.sBox = mode;
            } else if (['S-TEST', 'S-A', 'S-B', 'S-C', 'S-D', 'X-A', 'X-B', 'X-C'].indexOf(mode) >= 0) {
                na.namedParam = mode;
            } else if (['S-256-TEST', 'S-256-A', 'S-256-B', 'S-256-C', 'P-256', 'T-512-TEST', 'T-512-A',
                'T-512-B', 'X-256-A', 'X-256-B', 'T-256-TEST', 'T-256-A', 'T-256-B', 'S-256-B', 'T-256-C', 'S-256-C'].indexOf(mode) >= 0) {
                na.namedCurve = mode;
            } else if (['SC', 'CP', 'VN'].indexOf(mode) >= 0) {
                na.procreator = mode;

                // Encription GOST 28147 or GOST R 34.12
            } else if (na.name === 'GOST 28147' || na.name === 'GOST R 34.12' || na.name === 'RC2') {
                if (['ES', 'MAC', 'KW', 'MASK'].indexOf(mode) >= 0) {
                    na.mode = mode;
                } else if (['ECB', 'CFB', 'OFB', 'CTR', 'CBC'].indexOf(mode) >= 0) {
                    na.mode = 'ES';
                    na.block = mode;
                } else if (['CPKW', 'NOKW', 'SCKW'].indexOf(mode) >= 0) {
                    na.mode = 'KW';
                    na.keyWrapping = mode.replace('KW', '');
                } else if (['ZEROPADDING', 'PKCS5PADDING', 'NOPADDING', 'RANDOMPADDING', 'BITPADDING'].indexOf(mode) >= 0) {
                    na.padding = mode.replace('PADDING', '');
                } else if (['NOKM', 'CPKM'].indexOf(mode) >= 0) {
                    na.keyMeshing = mode.replace('KM', '');
                } else {
                    throw new Error('Algorithm ' + na.name + ' mode ' + mode + ' not supported');
                }

                // Digesting GOST 34.11
            } else if (na.name === 'GOST R 34.11' || na.name === 'SHA') {
                if (['HASH', 'KDF', 'HMAC', 'PBKDF2', 'PFXKDF', 'CPKDF'].indexOf(mode) >= 0) {
                    na.mode = mode;
                } else {
                    throw new Error('Algorithm ' + na.name + ' mode ' + mode + ' not supported');
                }

                // Signing GOST 34.10
            } else if (na.name === 'GOST R 34.10') {
                let hash = mode.replace(/[\.\s]/g, '');
                if (hash.indexOf('GOST') >= 0 && hash.indexOf('3411') >= 0) {
                    na.hash = mode;
                } else if (['SIGN', 'DH', 'MASK'].indexOf(mode)) {
                    na.mode = mode;
                } else {
                    throw new Error('Algorithm ' + na.name + ' mode ' + mode + ' not supported');
                }
            }
        });

        // Procreator
        na.procreator = algorithm.procreator || na.procreator || 'CP';

        // Key size
        switch (na.name) {
            case 'GOST R 34.10':
                na.keySize = na.length / (na.version === 1994 ? 4 : 8);
                break;
            case 'GOST R 34.11':
                na.keySize = 32;
                break;
            case 'GOST 28147':
            case 'GOST R 34.12':
                na.keySize = 32;
                break;
            case 'RC2':
                na.keySize = Math.ceil(na.length / 8);
                break;
            case 'SHA':
                na.keySize = na.length / 8;
                break;
        }

        // Encrypt additional modes
        if (na.mode === 'ES') {
            if (algorithm.block) {
                na.block = algorithm.block;
            } // ECB, CFB, OFB, CTR, CBC
            if (na.block) {
                na.block = na.block.toUpperCase();
            }
            if (algorithm.padding) {
                na.padding = algorithm.padding;
            } // NO, ZERO, PKCS5, RANDOM, BIT
            if (na.padding) {
                na.padding = na.padding.toUpperCase();
            }
            if (algorithm.shiftBits) {
                na.shiftBits = algorithm.shiftBits;
            } // 8, 16, 32, 64
            if (algorithm.keyMeshing) {
                na.keyMeshing = algorithm.keyMeshing;
            } // NO, CP
            if (na.keyMeshing) {
                na.keyMeshing = na.keyMeshing.toUpperCase();
            }
            // Default values
            if (method !== 'importKey' && method !== 'generateKey') {
                na.block = na.block || 'ECB';
                na.padding = na.padding || (na.block === 'CBC' || na.block === 'ECB' ? 'ZERO' : 'NO');
                if (na.block === 'CFB' || na.block === 'OFB') {
                    na.shiftBits = na.shiftBits || na.length;
                }
                na.keyMeshing = na.keyMeshing || 'NO';
            }
        }
        if (na.mode === 'KW') {
            if (algorithm.keyWrapping) {
                na.keyWrapping = algorithm.keyWrapping;
            } // NO, CP, SC
            if (na.keyWrapping) {
                na.keyWrapping = na.keyWrapping.toUpperCase();
            }
            if (method !== 'importKey' && method !== 'generateKey') {
                na.keyWrapping = na.keyWrapping || 'NO';
            }
        }

        // Paramsets
        ['sBox', 'namedParam', 'namedCurve', 'curve', 'param', 'modulusLength'].forEach((name) => {
            // tslint:disable-next-line:no-unused-expression FIXME что тут происходит?
            algorithm[name] && (na[name] = algorithm[name]);
        });
        // Default values
        if (method !== 'importKey' && method !== 'generateKey') {
            if (na.name === 'GOST 28147') {
                na.sBox = na.sBox || (na.procreator === 'SC' ? 'E-SC' : 'E-A'); // 'E-A', 'E-B', 'E-C', 'E-D', 'E-SC'
            } else if (na.name === 'GOST R 34.12' && na.length === 64) {
                na.sBox = 'E-Z';
            } else if (na.name === 'GOST R 34.11' && na.version === 1994) {
                na.sBox = na.sBox || (na.procreator === 'SC' ? 'D-SC' : 'D-A'); // 'D-SC'
            } else if (na.name === 'GOST R 34.10' && na.version === 1994) {
                na.namedParam = na.namedParam || (na.mode === 'DH' ? 'X-A' : 'S-A'); // 'S-B', 'S-C', 'S-D', 'X-B', 'X-C'
            } else if (na.name === 'GOST R 34.10' && na.version === 2001) {
                // @ts-ignore
                na.namedCurve = na.namedCurve || (na.length === 256 ?
                    na.procreator === 'SC' ? 'P-256' : (na.mode === 'DH' ? 'X-256-A' : 'S-256-A') : // 'S-256-B', 'S-256-C', 'X-256-B', 'T-256-A', 'T-256-B', 'T-256-C', 'P-256'
                    na.mode === 'T-512-A'); // 'T-512-B', 'T-512-C'
            } else if (na.name === 'GOST R 34.10' && na.version === 2012) {
                // @ts-ignore
                na.namedCurve = na.namedCurve || (na.length === 256 ?
                    na.procreator === 'SC' ? 'P-256' : (na.mode === 'DH' ? 'X-256-A' : 'S-256-A') : // 'S-256-B', 'S-256-C', 'X-256-B', 'T-256-A', 'T-256-B', 'T-256-C', 'P-256'
                    na.mode === 'T-512-A'); // 'T-512-B', 'T-512-C'
            }
        }

        // Vectors
        switch (na.mode) {
            case 'DH':
                algorithm.ukm && (na.ukm = algorithm.ukm);
                algorithm.public && (na.public = algorithm.public);
                break;
            case 'SIGN':
            case 'KW':
                algorithm.ukm && (na.ukm = algorithm.ukm);
                break;
            case 'ES':
            case 'MAC':
                algorithm.iv && (na.iv = algorithm.iv);
                break;
            case 'KDF':
                algorithm.label && (na.label = algorithm.label);
                algorithm.contex && (na.context = algorithm.contex);
                break;
            case 'PBKDF2':
                algorithm.salt && (na.salt = algorithm.salt);
                algorithm.iterations && (na.iterations = algorithm.iterations);
                algorithm.diversifier && (na.diversifier = algorithm.diversifier);
                break;
            case 'PFXKDF':
                algorithm.salt && (na.salt = algorithm.salt);
                algorithm.iterations && (na.iterations = algorithm.iterations);
                algorithm.diversifier && (na.diversifier = algorithm.diversifier);
                break;
            case 'CPKDF':
                algorithm.salt && (na.salt = algorithm.salt);
                algorithm.iterations && (na.iterations = algorithm.iterations);
                break;
        }

        // Verification method and modes
        if (method && (
            ((na.mode !== 'ES' && na.mode !== 'SIGN' && na.mode !== 'MAC' &&
                na.mode !== 'HMAC' && na.mode !== 'KW' && na.mode !== 'DH'
                && na.mode !== 'MASK') &&
                (method === 'generateKey')) ||
            ((na.mode !== 'ES') &&
                (method === 'encrypt' || method === 'decrypt')) ||
            ((na.mode !== 'SIGN' && na.mode !== 'MAC' && na.mode !== 'HMAC') &&
                (method === 'sign' || method === 'verify')) ||
            ((na.mode !== 'HASH') &&
                (method === 'digest')) ||
            ((na.mode !== 'KW' && na.mode !== 'MASK') &&
                (method === 'wrapKey' || method === 'unwrapKey')) ||
            ((na.mode !== 'DH' && na.mode !== 'PBKDF2' && na.mode !== 'PFXKDF' &&
                na.mode !== 'CPKDF' && na.mode !== 'KDF') &&
                (method === 'deriveKey' || method === 'deriveBits')))) {
            throw new Error('Algorithm mode ' + na.mode + ' not valid for method ' + method);
        }

        // Normalize hash algorithm
        algorithm.hash && (na.hash = algorithm.hash);
        if (na.hash) {
            if ((typeof na.hash === 'string' || na.hash instanceof String)
                && na.procreator) {
                na.hash = na.hash + '/' + na.procreator;
            }
            na.hash = this.normalize(na.hash, 'digest');
        }

        // Algorithm object identirifer
        algorithm.id && (na.id = algorithm.id);

        return na;
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

    checkKey(key: Key, method) {
        if (!key.algorithm) {
            throw new Error('Key algorithm not defined');
        }

        if (!key.algorithm.name) {
            throw new Error('Key algorithm name not defined');
        }

        let name = key.algorithm.name;
        let gostCipher = name === 'GOST 28147' || name === 'GOST R 34.12' || name === 'RC2';
        let gostDigest = name === 'GOST R 34.11' || name === 'SHA';
        let gostSign = name === 'GOST R 34.10';

        if (!gostCipher && !gostSign && !gostDigest) {
            throw new Error('Key algorithm ' + name + ' is unsupproted');
        }

        if (!key.type) {
            throw new Error('Key type not defined');
        }

        if (((gostCipher || gostDigest) && key.type !== 'secret') ||
            (gostSign && !(key.type === 'public' || key.type === 'private'))) {
            throw new Error('Key type ' + key.type + ' is not valid for algorithm ' + name);
        }

        if (!key.usages || !key.usages.indexOf) {
            throw new Error('Key usages not defined');
        }

        for (let i = 0, n = key.usages.length; i < n; i++) {
            let md = key.usages[i];
            if (((md === 'encrypt' || md === 'decrypt') && key.type !== 'secret') ||
                (md === 'sign' && key.type === 'public') ||
                (md === 'verify' && key.type === 'private')) {
                throw new Error('Key type ' + key.type + ' is not valid for ' + md);
            }
        }

        if (method) {
            if (key.usages.indexOf(method) === -1) {
                throw new Error('Key usages is not contain method ' + method);
            }
        }

        if (!key.buffer) {
            throw new Error('Key buffer is not defined');
        }

        let size = key.buffer.byteLength * 8;
        let keySize = 8 * key.algorithm.keySize;
        if ((key.type === 'secret' && size !== (keySize || 256) &&
            (key.usages.indexOf('encrypt') >= 0 || key.usages.indexOf('decrypt') >= 0)) ||
            (key.type === 'private' && !(size === 256 || size === 512)) ||
            (key.type === 'public' && !(size === 512 || size === 1024))) {
            throw new Error('Key buffer has wrong size ' + size + ' bit');
        }
    }

    extractKey(method, algorithm, key) {
        this.checkKey(key, method);
        if (algorithm) {
            let params;
            switch (algorithm.mode) {
                case 'ES':
                    params = ['sBox', 'keyMeshing', 'padding', 'block'];
                    break;
                case 'SIGN':
                    params = ['namedCurve', 'namedParam', 'sBox', 'curve', 'param', 'modulusLength'];
                    break;
                case 'MAC':
                    params = ['sBox'];
                    break;
                case 'KW':
                    params = ['keyWrapping', 'ukm'];
                    break;
                case 'DH':
                    params = ['namedCurve', 'namedParam', 'sBox', 'ukm', 'curve', 'param', 'modulusLength'];
                    break;
                case 'KDF':
                    params = ['context', 'label'];
                    break;
                case 'PBKDF2':
                    params = ['sBox', 'iterations', 'salt'];
                    break;
                case 'PFXKDF':
                    params = ['sBox', 'iterations', 'salt', 'diversifier'];
                    break;
                case 'CPKDF':
                    params = ['sBox', 'salt'];
                    break;
            }
            if (params) {
                params.forEach((name) => {
                    key.algorithm[name] && (algorithm[name] = key.algorithm[name]);
                });
            }
        }
        return key.buffer;
    }

    convertKey(algorithm, extractable, keyUsages, keyData, keyType: string) {
        let key: Key = {
            type: keyType || (algorithm.name === 'GOST R 34.10' ? 'private' : 'secret'),
            extractable: extractable || 'false',
            algorithm,
            usages: keyUsages || [],
            buffer: keyData
        } as Key;
        this.checkKey(key, undefined);
        return key;
    }

    convertKeyPair(publicAlgorithm, privateAlgorithm, extractable, keyUsages, publicBuffer, privateBuffer) {

        if (!keyUsages || !keyUsages.indexOf) {
            throw new SyntaxError('Key usages not defined');
        }

        let publicUsages = keyUsages.filter((value) => {
            return value !== 'sign';
        });
        let privateUsages = keyUsages.filter((value) => {
            return value !== 'verify';
        });

        return {
            publicKey: this.convertKey(publicAlgorithm, extractable, publicUsages, publicBuffer, 'public'),
            privateKey: this.convertKey(privateAlgorithm, extractable, privateUsages, privateBuffer, 'private')
        };
    }

    swapBytes(src) {
        if (src instanceof ArrayBuffer) {
            src = new Uint8Array(src);
        }
        let dst = new Uint8Array(src.length);
        for (let i = 0, n = src.length; i < n; i++) {
            dst[n - i - 1] = src[i];
        }
        return dst.buffer;
    }

    /*worker;
    tasks = [];
    sequence = 0;
    execute(algorithm, method, args) {
        return new Promise((resolve, reject) => {
            try {
                if (worker) {
                    let id = ++sequence;
                    tasks.push({
                        id: id,
                        resolve: resolve,
                        reject: reject
                    });
                    worker.postMessage({
                        id: id, algorithm: algorithm,
                        method: method, args: args
                    });
                } else {
                    if (root.gostEngine)
                        resolve(root.gostEngine.execute(algorithm, method, args));
                    else
                        reject(new OperationError('Module gostEngine not found'));
                }
            } catch (error) {
                reject(error);
            }
        });
    }*/
    subtleCryptoGost: SubtleCryptoGost;
}


export class SubtleCryptoGost implements SubtleCrypto {
    deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        throw new Error('Method not implemented.');
    }
    deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | ConcatParams | HkdfCtrParams | Pbkdf2Params | AesDerivedKeyParams | HmacImportParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        throw new Error('Method not implemented.');
    }
    digest(algorithm: string | Algorithm, data: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView): PromiseLike<ArrayBuffer> {
        throw new Error('Method not implemented.');
    }
   // exportKey(format: 'jwk', key: CryptoKey): PromiseLike<JsonWebKey>;
   // exportKey(format: 'raw' | 'pkcs8' | 'spki', key: CryptoKey): PromiseLike<ArrayBuffer>;
   // exportKey(format: string, key: CryptoKey): PromiseLike<ArrayBuffer | JsonWebKey>;
    exportKey(format: any, key: any): PromiseLike<any> {
        throw new Error('Method not implemented.');
    }
   // generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair>;
   // generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;
   // generateKey(algorithm: Pbkdf2Params | AesKeyGenParams | HmacKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    generateKey(algorithm: any, extractable: any, keyUsages: any): PromiseLike<any>{
        throw new Error('Method not implemented.');
    }
   // importKey(format: 'jwk', keyData: JsonWebKey, algorithm: string | HmacImportParams | RsaHashedImportParams | EcKeyImportParams | DhImportKeyParams | AesKeyAlgorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
   // importKey(format: 'raw' | 'pkcs8' | 'spki', keyData: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView, algorithm: string | HmacImportParams | RsaHashedImportParams | EcKeyImportParams | DhImportKeyParams | AesKeyAlgorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
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





    constructor(private gostCrypto: GostCrypto, private gostEngine: GostEngine) {
    }

    encrypt(algorithm, key, data): PromiseLike<any> {

            if (this.gostCrypto.checkNative(algorithm)) {
                return this.gostCrypto.subtle.encrypt(algorithm, key, data);
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

    decrypt(algorithm, key, data): PromiseLike<any>
    {
        if (this.gostCrypto.checkNative(algorithm)) {
            return this.gostCrypto.subtle.decrypt(algorithm, key, data);
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
        if (this.gostCrypto.checkNative(algorithm)) {
            return this.gostCrypto.subtle.sign(algorithm, key, data);
        }
        /*        return new Promise(call).then(function () {
            if (checkNative(algorithm))
                return rootCrypto.subtle.sign(algorithm, key, data);

            algorithm = normalize(algorithm, 'sign');
            var value = execute(algorithm, 'sign',
                    [extractKey('sign', algorithm, key), data]).then(function (data) {
                if (algorithm.procreator === 'SC' && algorithm.mode === 'SIGN') {
                    data = gostCrypto.asn1.GostSignature.encode(data);
                }
                return data;
            });
            return value;
        });*/
    }

    verify(algorithm, key, signature, data): PromiseLike<any>{
        if (this.gostCrypto.checkNative(algorithm)) {
            return this.gostCrypto.subtle.verify(algorithm, key, signature, data);
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
