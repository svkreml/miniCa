import {GostRandom} from '../gost-random/gost-random';
import {GostEngine} from '../gost-engine/gost-engine';

export class GostCrypto {
    subtle: SubtleCrypto = new SubtleCrypto();

    normalize(algorithm, method) {
        if (typeof algorithm === 'string' || algorithm instanceof String)
            algorithm = {name: algorithm};
        let name = algorithm.name;
        if (!name)
            throw new SyntaxError('Algorithm name not defined');
        // Extract algorithm modes from name
        let modes = name.split('/');
        modes = modes[0].split('-').concat(modes.slice(1));
        // Normalize the name with default modes
        let na: any = {}; // TODO заменить на класс дто
        name = modes[0].replace(/[\.\s]/g, ''), modes = modes.slice(1);
        if (name.indexOf('28147') >= 0) {
            na = {
                name: 'GOST 28147',
                version: 1989,
                mode: (algorithm.mode || (// ES, MAC, KW
                    (method === 'sign' || method === 'verify') ? 'MAC' :
                        (method === 'wrapKey' || method === 'unwrapKey') ? 'KW' : 'ES')).toUpperCase(),
                length: algorithm.length || 64
            };
        } else if (name.indexOf('3412') >= 0) {
            na = {
                name: 'GOST R 34.12',
                version: 2015,
                mode: (algorithm.mode || (// ES, MAC, KW
                    (method === 'sign' || method === 'verify') ? 'MAC' :
                        (method === 'wrapKey' || method === 'unwrapKey') ? 'KW' : 'ES')).toUpperCase(),
                length: algorithm.length || 64 // 128
            };
        } else if (name.indexOf('3411') >= 0) {
            na = {
                name: 'GOST R 34.11',
                version: 2012, // 1994
                mode: (algorithm.mode || (// HASH, KDF, HMAC, PBKDF2, PFXKDF, CPKDF
                    (method === 'deriveKey' || method === 'deriveBits') ? 'KDF' :
                        (method === 'sign' || method === 'verify') ? 'HMAC' : 'HASH')).toUpperCase(),
                length: algorithm.length || 256 // 512
            };
        } else if (name.indexOf('3410') >= 0) {
            na = {
                name: 'GOST R 34.10',
                version: 2012, // 1994, 2001
                mode: (algorithm.mode || (// SIGN, DH, MASK
                    (method === 'deriveKey' || method === 'deriveBits') ? 'DH' : 'SIGN')).toUpperCase(),
                length: algorithm.length || 256 // 512
            };
        } else if (name.indexOf('SHA') >= 0) {
            na = {
                name: 'SHA',
                version: (algorithm.length || 160) === 160 ? 1 : 2, // 1, 2
                mode: (algorithm.mode || (// HASH, KDF, HMAC, PBKDF2, PFXKDF
                    (method === 'deriveKey' || method === 'deriveBits') ? 'KDF' :
                        (method === 'sign' || method === 'verify') ? 'HMAC' : 'HASH')).toUpperCase(),
                length: algorithm.length || 160
            };
        } else if (name.indexOf('RC2') >= 0) {
            na = {
                name: 'RC2',
                version: 1,
                mode: (algorithm.mode || (// ES, MAC, KW
                    (method === 'sign' || method === 'verify') ? 'MAC' :
                        (method === 'wrapKey' || method === 'unwrapKey') ? 'KW' : 'ES')).toUpperCase(),
                length: algorithm.length || 32 // 1 - 1024
            };
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
        } else
            throw new Error('Algorithm not supported');

        // Compile modes
        modes.forEach((mode) => {
            mode = mode.toUpperCase();
            if (/^[0-9]+$/.test(mode)) {
                if ((['8', '16', '32'].indexOf(mode) >= 0) || (na.length === '128' && mode === '64')) { // Shift bits
                    if (na.mode === 'ES')

                        na.shiftBits = parseInt(mode);
                    else if (na.mode === 'MAC')

                        na.macLength = parseInt(mode);
                    else
                        throw new Error('Algorithm ' + na.name + ' mode ' + mode + ' not supported');
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
                    na.length = parseInt(mode);
                else if (['1000', '2000'].indexOf(mode) >= 0) // Iterations
                    na.iterations = parseInt(mode);
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
                } else
                    throw new Error('Algorithm ' + na.name + ' mode ' + mode + ' not supported');

                // Digesting GOST 34.11
            } else if (na.name === 'GOST R 34.11' || na.name === 'SHA') {
                if (['HASH', 'KDF', 'HMAC', 'PBKDF2', 'PFXKDF', 'CPKDF'].indexOf(mode) >= 0)
                    na.mode = mode;
                else
                    throw new Error('Algorithm ' + na.name + ' mode ' + mode + ' not supported');

                // Signing GOST 34.10
            } else if (na.name === 'GOST R 34.10') {
                let hash = mode.replace(/[\.\s]/g, '');
                if (hash.indexOf('GOST') >= 0 && hash.indexOf('3411') >= 0)
                    na.hash = mode;
                else if (['SIGN', 'DH', 'MASK'].indexOf(mode))
                    na.mode = mode;
                else
                    throw new Error('Algorithm ' + na.name + ' mode ' + mode + ' not supported');
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
            if (algorithm.block)
                na.block = algorithm.block; // ECB, CFB, OFB, CTR, CBC
            if (na.block)
                na.block = na.block.toUpperCase();
            if (algorithm.padding)
                na.padding = algorithm.padding; // NO, ZERO, PKCS5, RANDOM, BIT
            if (na.padding)
                na.padding = na.padding.toUpperCase();
            if (algorithm.shiftBits)
                na.shiftBits = algorithm.shiftBits; // 8, 16, 32, 64
            if (algorithm.keyMeshing)
                na.keyMeshing = algorithm.keyMeshing; // NO, CP
            if (na.keyMeshing)
                na.keyMeshing = na.keyMeshing.toUpperCase();
            // Default values
            if (method !== 'importKey' && method !== 'generateKey') {
                na.block = na.block || 'ECB';
                na.padding = na.padding || (na.block === 'CBC' || na.block === 'ECB' ? 'ZERO' : 'NO');
                if (na.block === 'CFB' || na.block === 'OFB')
                    na.shiftBits = na.shiftBits || na.length;
                na.keyMeshing = na.keyMeshing || 'NO';
            }
        }
        if (na.mode === 'KW') {
            if (algorithm.keyWrapping)
                na.keyWrapping = algorithm.keyWrapping; // NO, CP, SC
            if (na.keyWrapping)
                na.keyWrapping = na.keyWrapping.toUpperCase();
            if (method !== 'importKey' && method !== 'generateKey')
                na.keyWrapping = na.keyWrapping || 'NO';
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
                na.namedCurve = na.namedCurve || (na.length === 256 ?
                    na.procreator === 'SC' ? 'P-256' : (na.mode === 'DH' ? 'X-256-A' : 'S-256-A') : // 'S-256-B', 'S-256-C', 'X-256-B', 'T-256-A', 'T-256-B', 'T-256-C', 'P-256'
                    na.mode === 'T-512-A'); // 'T-512-B', 'T-512-C'
            } else if (na.name === 'GOST R 34.10' && na.version === 2012) {
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
                (method === 'deriveKey' || method === 'deriveBits'))))
            throw new Error('Algorithm mode ' + na.mode + ' not valid for method ' + method);

        // Normalize hash algorithm
        algorithm.hash && (na.hash = algorithm.hash);
        if (na.hash) {
            if ((typeof na.hash === 'string' || na.hash instanceof String)
                && na.procreator)
                na.hash = na.hash + '/' + na.procreator;
            na.hash = this.normalize(na.hash, 'digest');
        }

        // Algorithm object identirifer
        algorithm.id && (na.id = algorithm.id);

        return na;
    }

    checkNative(algorithm) {
        if (!this.subtle || !algorithm)
            return false;
        // Prepare name
        let name;
        name = (typeof algorithm === 'string' || algorithm instanceof String) ?
             algorithm : algorithm.name;
        if (!name)
            return false;
        name = name.toUpperCase();
        // Digest algorithm for key derivation
        if ((name.indexOf('KDF') >= 0 || name.indexOf('HMAC') >= 0) && algorithm.hash)
            return this.checkNative(algorithm.hash);
        // True if no supported names
        return name.indexOf('GOST') === -1 &&
            name.indexOf('SHA-1') === -1 &&
            name.indexOf('RC2') === -1 &&
            name.indexOf('?DES') === -1;
    }

}
