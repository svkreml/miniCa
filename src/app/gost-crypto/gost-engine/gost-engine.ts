import {GostSign} from '../gost-sign/gost-sign';
import {GostDigest} from '../gost-digest/gost-digest';
import {GostCipher} from '../gost-cipher/gost-cipher';

export class GostEngine {

    defineEngine(method, algorithm) {
        if (!algorithm) {
            throw new Error('Algorithm not defined');
        }

        if (!algorithm.name) {
            throw new Error('Algorithm name not defined');
        }

        const name = algorithm.name;
        const mode = algorithm.mode;
        if ((name === 'GOST 28147' || name === 'GOST R 34.12' || name === 'RC2') && (method === 'generateKey' ||
            (mode === 'MAC' && (method === 'sign' || method === 'verify')) ||
            ((mode === 'KW' || mode === 'MASK') && (method === 'wrapKey' || method === 'unwrapKey')) ||
            ((!mode || mode === 'ES') && (method === 'encrypt' || method === 'decrypt')))) {
            return 'GostCipher';

        } else if ((name === 'GOST R 34.11' || name === 'SHA') && (method === 'digest' ||
            (mode === 'HMAC' && (method === 'sign' || method === 'verify' || method === 'generateKey')) ||
            ((mode === 'KDF' || mode === 'PBKDF2' || mode === 'PFXKDF' || mode === 'CPKDF') &&
                (method === 'deriveKey' || method === 'deriveBits' || method === 'generateKey')))) {
            return 'GostDigest';

        } else if (name === 'GOST R 34.10' && (method === 'generateKey' ||
            ((!mode || mode === 'SIGN') && (method === 'sign' || method === 'verify')) ||
            (mode === 'MASK' && (method === 'wrapKey' || method === 'unwrapKey')) ||
            (mode === 'DH' && (method === 'deriveKey' || method === 'deriveBits')))) {
            return 'GostSign';
        } else {
            throw new Error('Algorithm ' + name + '-' + mode + ' is not valid for ' + method);
 }
    }


    execute(algorithm, method, args) {
        // Define engine for GOST algorithms

        const engine = this.defineEngine(method, algorithm);
        // Create cipher

        const cipher = this['get' + engine](algorithm);
        // Execute method
        return cipher[method].apply(cipher, args);
    }

    getGostCipher(algorithm) {
        return new GostCipher(algorithm);
    }

    getGostDigest(algorithm) {
        return new GostDigest(algorithm);
    }

    getGostSign(algorithm) {
        return new GostSign(algorithm);
    }


    constructor() {
    }

}
