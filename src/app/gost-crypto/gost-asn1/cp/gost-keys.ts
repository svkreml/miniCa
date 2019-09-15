import {GostCrypto} from '../../gost-crypto/gost-crypto';
import {GostRandom} from '../../gost-random/gost-random';
import {expand} from 'rxjs/operators';
import {GostSubtleCrypto} from '../../gost-subtle/gost-subtle-crypto';
import {GostEngine} from '../../gost-engine/gost-engine';
import {Chars} from '../../gost-coding/gost-coding';

export class GostKeys {
    subtle: GostSubtleCrypto = new GostSubtleCrypto(new GostCrypto(), new GostEngine());

/*
    public computeContainerMAC(algorithm, content) {
        let mac = expand({name: 'GOST 28147-MAC'}, algorithm.encParams);

        let keyData = new Uint8Array([// 32 zero bytes
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        return this.subtle.importKey('raw', keyData, mac, false, ['sign']).then(macKey => {
            //                let buffer = new Uint8Array(content.encode());
            //                console.log(coding.Hex.encode(buffer));
            //                if (lastBuffer && lastBuffer.length === buffer.length) {
            //                    for (let i = 0; i < buffer.length; i++)
            //                        if (lastBuffer[i] !== buffer[i])
            //                            console.log('diff at ' + i);
            //                } else
            //                    console.log('diff length');
            //                lastBuffer = buffer;
            // Mac for content
            return this.subtle.sign(mac, macKey, content.encode());
        });
    }
*/

    public getSeed(length): ArrayBuffer {
        let seed = new Uint8Array(length);
        GostRandom.getRandomValues(seed);
        return seed.buffer;
    }

    public equalBuffers(r1, r2) {
        let s1 = new Uint8Array(r1);
        let s2 = new Uint8Array(r2);
        if (s1.length !== s2.length)
            return false;
        for (let i = 0, n = s1.length; i < n; i++)
            if (s1[i] !== s2[i])
                return false;
        return true;
    }


/*    public computePasswordMAC(algorithm, password, salt) {
        let mac = expand({name: 'GOST 28147-MAC'}, algorithm.encParams);

        // Derive password
        return this.derivePasswordKey(algorithm, password, salt).then( (macKey) => {
            // Mac for 16 zero bytes
            return this.subtle.sign(mac, macKey,
                new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        });
    }*/


    // Derive password key
    public derivePasswordKey(algorithm, password, salt) {
        let hash = this.isVersion2012(algorithm) ? 'GOST R 34.11-256' : 'GOST R 34.11-94/' + (algorithm.sBox || 'D-A');
        let derivation = {
            name: 'CPKDF',
            hash,
            salt,
            iterations: password ? 2000 : 2};

        // Import password
        return this.subtle.importKey('raw', this.passwordData(derivation, password),
            derivation, false, ['deriveKey', 'deriveBits']).then( (baseKey) => {

            // Derive key
            return this.subtle.deriveKey(derivation, baseKey, 'GOST 28147',
                false, ['sign', 'verify', 'encrypt', 'decrypt']);
        });
    }

    public isVersion2012(algorithm) {
        return !((algorithm.name.indexOf('-94') >= 0 || algorithm.name.indexOf('-2001') >= 0 ||
            algorithm.version === 1994 || algorithm.version === 2001));
    }

    public passwordData(derivation, password) {
        if (!password)
            return new ArrayBuffer(0);
        if (derivation.name.indexOf('CPKDF') >= 0) {
            // CryptoPro store password
            let r = [];
            for (let i = 0; i < password.length; i++) {
                let c = password.charCodeAt(i);
                r.push(c & 0xff);
                r.push(c >>> 8 & 0xff);
                r.push(0);
                r.push(0);
            }
            return new Uint8Array(r).buffer;
        } else if (derivation.name.indexOf('PFXKDF') >= 0)
        // PKCS#12 unicode password
            return Chars.decode(password + '\0', 'unicode');
        else
        // PKCS#5 password mode
            return Chars.decode(password, 'utf8');
    }
}
