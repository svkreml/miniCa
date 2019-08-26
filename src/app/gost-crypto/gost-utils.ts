export class GostUtils {
    public static buffer(d: Uint8Array): ArrayBuffer { // FixMe уточнить тип
        if (d instanceof ArrayBuffer) {
            return d;
        } else if (d && d.buffer && d.buffer instanceof ArrayBuffer) {
            return d.byteOffset === 0 && d.byteLength === d.buffer.byteLength ?
                d.buffer : new Uint8Array(new Uint8Array(d, d.byteOffset, d.byteLength)).buffer;
        } else {
            throw new Error('CryptoOperationData required');
        }
    }
}


/**
 * HEX conversion
 */
export class Hex {

    /**
     * Hex.decode(s, endean) convert HEX string s to CryptoOperationData in endean mode
     */
    public static decode(s: string): ArrayBufferLike {
        let endean;

        s = s.replace(/[^A-fa-f0-9]/g, '');
        let n = Math.ceil(s.length / 2);
        let r = new Uint8Array(n);
        s = (s.length % 2 > 0 ? '0' : '') + s;
        if (endean && ((typeof endean !== 'string') ||
            (endean.toLowerCase().indexOf('little') < 0))) {
            for (let i = 0; i < n; i++) {
                r[i] = parseInt(s.substr((n - i - 1) * 2, 2), 16);
            }
        } else {
            for (let i = 0; i < n; i++) {
                r[i] = parseInt(s.substr(i * 2, 2), 16);
            }
        }
        return r.buffer;
    }

    /**
     * Hex.encode(data, endean) convert CryptoOperationData data to HEX string in endean mode
     */
    public static encode(data): string {
        let endean;
        let s = [];
        let d = new Uint8Array(GostUtils.buffer(data));
        let n = d.length;
        if (endean && ((typeof endean !== 'string') ||
            (endean.toLowerCase().indexOf('little') < 0))) {
            for (let i = 0; i < n; i++) {
                let j = n - i - 1;
                s[j] = (j > 0 && j % 32 === 0 ? '\r\n' : '') +
                    ('00' + d[i].toString(16)).slice(-2);
            }
        } else {
            for (let i = 0; i < n; i++) {
                s[i] = (i > 0 && i % 32 === 0 ? '\r\n' : '') +
                    ('00' + d[i].toString(16)).slice(-2);
            }
        }
        return s.join('');
    } // </editor-fold>
}
