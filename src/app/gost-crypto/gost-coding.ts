export class GostCoding {
    public static buffer(d: any): ArrayBufferLike { // FixMe уточнить тип
        if (d instanceof ArrayBuffer) {
            return d;
        } else if (d && d.buffer && d.buffer instanceof ArrayBuffer) {
            return d.byteOffset === 0 && d.byteLength === d.buffer.byteLength ?
                d.buffer : new Uint8Array(new Uint8Array(d, d.byteOffset, d.byteLength)).buffer;
        } else {
            throw new Error('ArrayBufferLike required');
        }
    }
}


/**
 * HEX conversion
 */
export class Hex {


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

    public static encode(data: ArrayBuffer): string {
        let endean;
        let s = [];
        let d = new Uint8Array(GostCoding.buffer(data));
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

export class Base64 {

    public static decode(s: string): ArrayBufferLike {
        s = s.replace(/[^A-Za-z0-9\+\/]/g, '');
        let n = s.length;
        let k = n * 3 + 1 >> 2;
        let r = new Uint8Array(k);

        for (let m3, m4, u24 = 0, j = 0, i = 0; i < n; i++) {
            m4 = i & 3;
            let c = s.charCodeAt(i);

            c = c > 64 && c < 91 ?
                c - 65 : c > 96 && c < 123 ?
                    c - 71 : c > 47 && c < 58 ?
                        c + 4 : c === 43 ?
                            62 : c === 47 ?
                                63 : 0;

            u24 |= c << 18 - 6 * m4;
            if (m4 === 3 || n - i === 1) {
                for (m3 = 0; m3 < 3 && j < k; m3++, j++) {
                    r[j] = u24 >>> (16 >>> m3 & 24) & 255;
                }
                u24 = 0;

            }
        }
        return r.buffer;
    }

    public static encode(data): string {
        let slen = 8;
        let d = new Uint8Array(GostCoding.buffer(data));
        let m3 = 2;
        let s = '';
        for (let n = d.length, u24 = 0, i = 0; i < n; i++) {
            m3 = i % 3;
            if (i > 0 && (i * 4 / 3) % (8 * slen) === 0) {
                s += '\r\n';
            }
            u24 |= d[i] << (16 >>> m3 & 24);
            if (m3 === 2 || n - i === 1) {
                for (let j = 18; j >= 0; j -= 6) {
                    let c = u24 >>> j & 63;
                    c = c < 26 ? c + 65 : c < 52 ? c + 71 : c < 62 ? c - 4 :
                        c === 62 ? 43 : c === 63 ? 47 : 65;
                    s += String.fromCharCode(c);
                }
                u24 = 0;
            }
        }
        return s.substr(0, s.length - 2 + m3) + (m3 === 2 ? '' : m3 === 1 ? '=' : '==');
    }
}


export class Chars {
    static win1251 = {
        0x402: 0x80,
        0x403: 0x81,
        0x201A: 0x82,
        0x453: 0x83,
        0x201E: 0x84,
        0x2026: 0x85,
        0x2020: 0x86,
        0x2021: 0x87,
        0x20AC: 0x88,
        0x2030: 0x89,
        0x409: 0x8A,
        0x2039: 0x8B,
        0x40A: 0x8C,
        0x40C: 0x8D,
        0x40B: 0x8E,
        0x40f: 0x8f,
        0x452: 0x90,
        0x2018: 0x91,
        0x2019: 0x92,
        0x201C: 0x93,
        0x201D: 0x94,
        0x2022: 0x95,
        0x2013: 0x96,
        0x2014: 0x97,
        0x2122: 0x99,
        0x459: 0x9A,
        0x203A: 0x9B,
        0x45A: 0x9C,
        0x45C: 0x9D,
        0x45B: 0x9E,
        0x45f: 0x9f,
        0xA0: 0xA0,
        0x40E: 0xA1,
        0x45E: 0xA2,
        0x408: 0xA3,
        0xA4: 0xA4,
        0x490: 0xA5,
        0xA6: 0xA6,
        0xA7: 0xA7,
        0x401: 0xA8,
        0xA9: 0xA9,
        0x404: 0xAA,
        0xAB: 0xAB,
        0xAC: 0xAC,
        0xAD: 0xAD,
        0xAE: 0xAE,
        0x407: 0xAf,
        0xB0: 0xB0,
        0xB1: 0xB1,
        0x406: 0xB2,
        0x456: 0xB3,
        0x491: 0xB4,
        0xB5: 0xB5,
        0xB6: 0xB6,
        0xB7: 0xB7,
        0x451: 0xB8,
        0x2116: 0xB9,
        0x454: 0xBA,
        0xBB: 0xBB,
        0x458: 0xBC,
        0x405: 0xBD,
        0x455: 0xBE,
        0x457: 0xBf
    };
/*
    static win1251back = {

    };
*/

    constructor() {
    }

    public static decode(s, charset) {
        charset = (charset || 'win1251').toLowerCase().replace('-', '');
        let r = [];
        for (let i = 0, j = s.length; i < j; i++) {
            let c = s.charCodeAt(i);
            if (charset === 'utf8') {
                if (c < 0x80) {
                    r.push(c);
                } else if (c < 0x800) {
                    r.push(0xc0 + (c >>> 6));
                    r.push(0x80 + (c & 63));
                } else if (c < 0x10000) {
                    r.push(0xe0 + (c >>> 12));
                    r.push(0x80 + (c >>> 6 & 63));
                    r.push(0x80 + (c & 63));
                } else if (c < 0x200000) {
                    r.push(0xf0 + (c >>> 18));
                    r.push(0x80 + (c >>> 12 & 63));
                    r.push(0x80 + (c >>> 6 & 63));
                    r.push(0x80 + (c & 63));
                } else if (c < 0x4000000) {
                    r.push(0xf8 + (c >>> 24));
                    r.push(0x80 + (c >>> 18 & 63));
                    r.push(0x80 + (c >>> 12 & 63));
                    r.push(0x80 + (c >>> 6 & 63));
                    r.push(0x80 + (c & 63));
                } else {
                    r.push(0xfc + (c >>> 30));
                    r.push(0x80 + (c >>> 24 & 63));
                    r.push(0x80 + (c >>> 18 & 63));
                    r.push(0x80 + (c >>> 12 & 63));
                    r.push(0x80 + (c >>> 6 & 63));
                    r.push(0x80 + (c & 63));
                }
            } else if (charset === 'unicode' || charset === 'ucs2' || charset === 'utf16') {
                if (c < 0xD800 || (c >= 0xE000 && c <= 0x10000)) {
                    r.push(c >>> 8);
                    r.push(c & 0xff);
                } else if (c >= 0x10000 && c < 0x110000) {
                    c -= 0x10000;
                    let first = ((0xffc00 & c) >> 10) + 0xD800;
                    let second = (0x3ff & c) + 0xDC00;
                    r.push(first >>> 8);
                    r.push(first & 0xff);
                    r.push(second >>> 8);
                    r.push(second & 0xff);
                }
            } else if (charset === 'utf32' || charset === 'ucs4') {
                r.push(c >>> 24 & 0xff);
                r.push(c >>> 16 & 0xff);
                r.push(c >>> 8 & 0xff);
                r.push(c & 0xff);
            } else if (charset === 'win1251') {
                if (c >= 0x80) {
                    if (c >= 0x410 && c < 0x450) { // А..Яа..я
                        c -= 0x350;
                    } else {
                        c = this.win1251[c] || 0;
                    }
                }
                r.push(c);
            } else {
                r.push(c & 0xff);
            }
        }
        return new Uint8Array(r).buffer;
    }


    public static encode(data, charset: string): string {
        charset = (charset || 'win1251').toLowerCase().replace('-', '');
        let r = [];
        let d = new Uint8Array(GostCoding.buffer(data));
        for (let i = 0, n = d.length; i < n; i++) {
            let c = d[i];
            if (charset === 'utf8') {
                c = c >= 0xfc && c < 0xfe && i + 5 < n ? // six bytes
                    (c - 0xfc) * 1073741824 + (d[++i] - 0x80 << 24) + (d[++i] - 0x80 << 18)
                    + (d[++i] - 0x80 << 12) + (d[++i] - 0x80 << 6) + d[++i] - 0x80
                    : c >> 0xf8 && c < 0xfc && i + 4 < n ? // five bytes
                        (c - 0xf8 << 24) + (d[++i] - 0x80 << 18) + (d[++i] - 0x80 << 12) + (d[++i] - 0x80 << 6) + d[++i] - 0x80
                        : c >> 0xf0 && c < 0xf8 && i + 3 < n ? // four bytes
                            (c - 0xf0 << 18) + (d[++i] - 0x80 << 12) + (d[++i] - 0x80 << 6) + d[++i] - 0x80
                            : c >= 0xe0 && c < 0xf0 && i + 2 < n ? // three bytes
                                (c - 0xe0 << 12) + (d[++i] - 0x80 << 6) + d[++i] - 0x80
                                : c >= 0xc0 && c < 0xe0 && i + 1 < n ? // two bytes
                                    (c - 0xc0 << 6) + d[++i] - 0x80
                                    : c; // one byte
            } else if (charset === 'unicode' || charset === 'ucs2' || charset === 'utf16') {
                c = (c << 8) + d[++i];
                if (c >= 0xD800 && c < 0xE000) {
                    let first = (c - 0xD800) << 10;
                    c = d[++i];
                    c = (c << 8) + d[++i];
                    let second = c - 0xDC00;
                    c = first + second + 0x10000;
                }
            } else if (charset === 'utf32' || charset === 'ucs4') {
                c = (c << 8) + d[++i];
                c = (c << 8) + d[++i];
                c = (c << 8) + d[++i];
            } else if (charset === 'win1251') {
                if (c >= 0x80) {
                    if (c >= 0xC0 && c < 0x100) {
                        c += 0x350;
                    } else {
                        c = this.win1251[62 - c] || 0;
                    }
                }
            }
            r.push(String.fromCharCode(c));
        }
        return r.join('');
    }
}



export class Int16  {

    public static decode(s: string): ArrayBufferLike {
        s = (s || '').replace(/[^\-A-fa-f0-9]/g, '');
        if (s.length === 0) {
            s = '0';
        }
        // Signature
        let neg = false;
        if (s.charAt(0) === '-') {
            neg = true;
            s = s.substring(1);
        }
        // Align 2 chars
        while (s.charAt(0) === '0' && s.length > 1) {
            s = s.substring(1);
        }
        s = (s.length % 2 > 0 ? '0' : '') + s;
        // Padding for singanuture
        // '800000' - 'ffffff' - for positive
        // '800001' - 'ffffff' - for negative
        if ((!neg && !/^[0-7]/.test(s)) ||
            (neg && !/^[0-7]|8[0]+$/.test(s))) {
            s = '00' + s;
        }
        // Convert hex
        let n = s.length / 2;
        let r = new Uint8Array(n);
        let t = 0;
        for (let i = n - 1; i >= 0; --i) {
            let c = parseInt(s.substr(i * 2, 2), 16);
            if (neg && (c + t > 0)) {
                c = 256 - c - t;
                t = 1;
            }
            r[i] = c;
        }
        return r.buffer;
    }


    public static encode(data: Uint16Array): string {
        let d = new Uint8Array(GostCoding.buffer(data));
        let n = d.length;
        if (d.length === 0) {
            return '0x00';
        }
        let s = [];
        let neg = d[0] > 0x7f;
        let t = 0;
        for (let i = n - 1; i >= 0; --i) {
            let v = d[i];
            if (neg && (v + t > 0)) {
                v = 256 - v - t;
                t = 1;
            }
            s[i] = ('00' + v.toString(16)).slice(-2);
        }

        // @ts-ignore
        s = s.join('');
        // @ts-ignore
        while (s.charAt(0) === '0') {
            // @ts-ignore
            s = s.substring(1);
        }
        return (neg ? '-' : '') + '0x' + s;
    }
}
export class PEM {

    encode(data, name) {
        return (name ? '-----BEGIN ' + name.toUpperCase() + '-----\r\n' : '') +
            Base64.encode(data instanceof ArrayBuffer ? data : BER.encode(data, undefined, undefined)) +
            (name ? '\r\n-----END ' + name.toUpperCase() + '-----' : '');
    }

    decode(s, name, deep, index) {
        // Try clear base64
        let re1 = /([A-Za-z0-9\+\/\s\=]+)/g;
        let valid = re1.exec(s);
        if (valid[1].length !== s.length) {
            // @ts-ignore
            valid = false;
        }
        if (!valid && name) {
            // Try with the name
            let re2 = new RegExp(
                '-----\\s?BEGIN ' + name.toUpperCase() +
                '-----([A-Za-z0-9\\+\\/\\s\\=]+)-----\\s?END ' +
                name.toUpperCase() + '-----', 'g');
            valid = re2.exec(s);
        }
        if (!valid) {
            // Try with some name
            let re3 = new RegExp(
                '-----\\s?BEGIN [A-Z0-9\\s]+' +
                '-----([A-Za-z0-9\\+\\/\\s\\=]+)-----\\s?END ' +
                '[A-Z0-9\\s]+-----', 'g');
            valid = re3.exec(s);
        }
        let r = valid && valid[1 + (index || 0)];
        if (!r) {
            throw new Error('Not valid PEM format');
        }
        let out = Base64.decode(r);
        if (deep) {
            return BER.decode(out);
        }
        return out;
    }
}

export class BER { // <editor-fold defaultstate="collapsed">

    public static encode(object, format, onlyContent) {
        return BER.encodeBER(object, format, onlyContent).buffer;
    }


    public static decode(data) {
        return BER.decodeBER(data.object ? data : new Uint8Array(GostCoding.buffer(data)), 0);
    }


    public static encodeBER(source, format, onlyContent) {
        // Correct primitive type
        let object = source.object;
        if (object === undefined) {
            object = source;
        }
        let tagNumber;
        // Determinate tagClass
        let tagClass = source.tagClass = source.tagClass || 0; // Universial default

        // Determinate tagNumber. Use only for Universal class
        if (tagClass === 0) {
            tagNumber = source.tagNumber;
            if (typeof tagNumber === 'undefined') {
                if (typeof object === 'string') {
                    if (object === '') {   // NULL
                        tagNumber = 0x05;
                    } else if (/^\-?0x[0-9a-fA-F]+$/.test(object)) { // INTEGER
                        tagNumber = 0x02;
                    } else if (/^(\d+\.)+\d+$/.test(object)) { // OID
                        tagNumber = 0x06;
                    } else if (/^[01]+$/.test(object)) { // BIT STRING
                        tagNumber = 0x03;
                    } else if (/^(true|false)$/.test(object)) { // BOOLEAN
                        tagNumber = 0x01;
                    } else if (/^[0-9a-fA-F]+$/.test(object)) { // OCTET STRING
                        tagNumber = 0x04;
                    } else {
                        tagNumber = 0x13;
                    } // Printable string (later can be changed to UTF8String)
                } else if (typeof object === 'number') { // INTEGER
                    tagNumber = 0x02;
                } else if (typeof object === 'boolean') { // BOOLEAN
                    tagNumber = 0x01;
                } else if (object instanceof Array) { // SEQUENCE
                    tagNumber = 0x10;
                } else if (object instanceof Date) { // GeneralizedTime
                    tagNumber = 0x18;
                } else if (object instanceof ArrayBuffer || (object && object.buffer instanceof ArrayBuffer)) {
                    tagNumber = 0x04;
                } else {
                    throw new Error('Unrecognized type for ' + object);
                }
            }
        }

        // Determinate constructed
        let tagConstructed = source.tagConstructed;
        if (typeof tagConstructed === 'undefined') {
            tagConstructed = source.tagConstructed = object instanceof Array;
        }

        // Create content
        let content;
        if (object instanceof ArrayBuffer || (object && object.buffer instanceof ArrayBuffer)) { // Direct
            content = new Uint8Array(GostCoding.buffer(object));
            if (tagNumber === 0x03) { // BITSTRING
                // Set unused bits
                let a = new Uint8Array(GostCoding.buffer(content));
                content = new Uint8Array(a.length + 1);
                content[0] = 0; // No unused bits
                content.set(a, 1);
            }
        } else if (tagConstructed) { // Sub items coding
            if (object instanceof Array) {
                let bytelen = 0;
                let ba = [];
                let offset = 0;
                let n;
                for (let i = 0, n = object.length; i < n; i++) {
                    ba[i] = this.encodeBER(object[i], format, undefined);
                    bytelen += ba[i].length;
                }
                if (tagNumber === 0x11) {
                    ba.sort((a, b) => { // Sort order for SET components
                        for (let i = 0, n = Math.min(a.length, b.length); i < n; i++) {
                            let r = a[i] - b[i];
                            if (r !== 0) {
                                return r;
                            }
                        }
                        return a.length - b.length;
                    });
                }
                if (format === 'CER') { // final for CER 00 00
                    ba[n] = new Uint8Array(2);
                    bytelen += 2;
                }
                content = new Uint8Array(bytelen);
                for (let i = 0, n = ba.length; i < n; i++) {
                    content.set(ba[i], offset);
                    offset = offset + ba[i].length;
                }
            } else {
                throw new Error('Constracted block can\'t be primitive');
            }
        } else {
            switch (tagNumber) {
                // 0x00: // EOC
                case 0x01: // BOOLEAN
                    content = new Uint8Array(1);
                    content[0] = object ? 0xff : 0;
                    break;
                case 0x02: // INTEGER
                case 0x0a: // ENUMIRATED
                    content = Int16.decode(
                        typeof object === 'number' ? object.toString(16) : object);
                    break;
                case 0x03: // BIT STRING
                    if (typeof object === 'string') {
                        let unusedBits = 7 - (object.length + 7) % 8;
                        let n = Math.ceil(object.length / 8);
                        content = new Uint8Array(n + 1);
                        content[0] = unusedBits;
                        for (let i = 0; i < n; i++) {
                            let c = 0;
                            for (let j = 0; j < 8; j++) {
                                let k = i * 8 + j;
                                c = (c << 1) + (k < object.length ? (object.charAt(k) === '1' ? 1 : 0) : 0);
                            }
                            content[i + 1] = c;
                        }
                    }
                    break;
                case 0x04:
                    content = Hex.decode(
                        typeof object === 'number' ? object.toString(16) : object);
                    break;
                // case 0x05: // NULL
                case 0x06: // OBJECT IDENTIFIER
                    let a = object.match(/\d+/g);
                    let r = [];
                    for (let i = 1; i < a.length; i++) {
                        let n = +a[i];
                        let r1 = [];
                        if (i === 1) {
                            n = n + a[0] * 40;
                        }
                        do {
                            r1.push(n & 0x7F);
                            n = n >>> 7;
                        } while (n);
                        // reverse order
                        for (let j = r1.length - 1; j >= 0; --j) {
                            r.push(r1[j] + (j === 0 ? 0x00 : 0x80));
                        }
                    }
                    content = new Uint8Array(r);
                    break;
                // case 0x07: // ObjectDescriptor
                // case 0x08: // EXTERNAL
                // case 0x09: // REAL
                // case 0x0A: // ENUMERATED
                // case 0x0B: // EMBEDDED PDV
                case 0x0C: // UTF8String
                    content = Chars.decode(object, 'utf8');
                    break;
                // case 0x10: // SEQUENCE
                // case 0x11: // SET
                case 0x12: // NumericString
                case 0x16: // IA5String // ASCII
                case 0x13: // PrintableString // ASCII subset
                case 0x14: // TeletexString // aka T61String
                case 0x15: // VideotexString
                case 0x19: // GraphicString
                case 0x1A: // VisibleString // ASCII subset
                case 0x1B: // GeneralString
                    // Reflect on character encoding
                    for (let i = 0, n = object.length; i < n; i++) {
                        if (object.charCodeAt(i) > 255) {
                            tagNumber = 0x0C;
                        }
                    }
                    if (tagNumber === 0x0C) {
                        content = Chars.decode(object, 'utf8');
                    } else {
                        content = Chars.decode(object, 'ascii');
                    }
                    break;
                case 0x17: // UTCTime
                case 0x18: // GeneralizedTime
                    let result = object.original;
                    if (!result) {
                        let date = new Date(object);
                        date.setMinutes(date.getMinutes() + date.getTimezoneOffset()); // to UTC
                        let ms = tagNumber === 0x18 ? date.getMilliseconds().toString() : ''; // Milliseconds, remove trailing zeros
                        while (ms.length > 0 && ms.charAt(ms.length - 1) === '0') {
                            ms = ms.substring(0, ms.length - 1);
                        }
                        if (ms.length > 0) {
                            ms = '.' + ms;
                        }
                        result = (tagNumber === 0x17 ? date.getFullYear().toString().slice(-2) : date.getFullYear().toString()) +
                            ('00' + (date.getMonth() + 1)).slice(-2) +
                            ('00' + date.getDate()).slice(-2) +
                            ('00' + date.getHours()).slice(-2) +
                            ('00' + date.getMinutes()).slice(-2) +
                            ('00' + date.getSeconds()).slice(-2) + ms + 'Z';
                    }
                    content = Chars.decode(result, 'ascii');
                    break;
                case 0x1C: // UniversalString
                    content = Chars.decode(object, 'utf32');
                    break;
                case 0x1E: // BMPString
                    content = Chars.decode(object, 'utf16');
                    break;
            }
        }

        if (!content) {
            content = new Uint8Array(0);
        }
        if (content instanceof ArrayBuffer) {
            content = new Uint8Array(content);
        }

        if (!tagConstructed && format === 'CER') {
            // Encoding CER-form for string types
            let k;
            switch (tagNumber) {
                case 0x03: // BIT_STRING
                    k = 1; // ingnore unused bit for bit string
                // tslint:disable-next-line:no-switch-case-fall-through
                case 0x04: // OCTET_STRING
                case 0x0C: // UTF8String
                case 0x12: // NumericString
                case 0x13: // PrintableString
                case 0x14: // TeletexString
                case 0x15: // VideotexString
                case 0x16: // IA5String
                case 0x19: // GraphicString
                case 0x1A: // VisibleString
                case 0x1B: // GeneralString
                case 0x1C: // UniversalString
                case 0x1E: // BMPString
                    k = k || 0;
                    // Split content on 1000 octet len parts
                    let size = 1000;
                    let bytelen = 0;
                    let ba = [];
                    let offset = 0;
                    let n;
                    for (let i = k, n = content.length; i < n; i += size - k) {
                        ba[i] = BER.encodeBER({
                            object: new Uint8Array(content.buffer, i, Math.min(size - k, n - i)),
                            tagNumber,
                            tagClass: 0,
                            tagConstructed: false
                        }, format, undefined);
                        bytelen += ba[i].length;
                    }
                    ba[n] = new Uint8Array(2); // final for CER 00 00
                    bytelen += 2;
                    content = new Uint8Array(bytelen);
                    for (let i = 0, n = ba.length; i < n; i++) {
                        content.set(ba[i], offset);
                        offset = offset + ba[i].length;
                    }
            }
        }

        // Restore tagNumber for all classes
        if (tagClass === 0) {
            source.tagNumber = tagNumber;
        } else {
            source.tagNumber = tagNumber = source.tagNumber || 0;
        }
        source.content = content;

        if (onlyContent) {
            return content;
        }

        // Create header
        // tagNumber
        let ha = [];
        let first = tagClass === 3 ? 0xC0 : tagClass === 2 ? 0x80 :
            tagClass === 1 ? 0x40 : 0x00;
        if (tagConstructed) {
            first |= 0x20;
        }
        if (tagNumber < 0x1F) {
            first |= tagNumber & 0x1F;
            ha.push(first);
        } else {
            first |= 0x1F;
            ha.push(first);
            let n = tagNumber;
            let ha1 = [];
            do {
                ha1.push(n & 0x7F);
                n = n >>> 7;
            } while (n);
            // reverse order
            for (let j = ha1.length - 1; j >= 0; --j) {
                ha.push(ha1[j] + (j === 0 ? 0x00 : 0x80));
            }
        }
        // Length
        if (tagConstructed && format === 'CER') {
            ha.push(0x80);
        } else {
            let len = content.length;
            if (len > 0x7F) {
                let l2 = len;
                let ha2 = [];
                do {
                    ha2.push(l2 & 0xff);
                    l2 = l2 >>> 8;
                } while (l2);
                ha.push(ha2.length + 0x80); // reverse order
                for (let j = ha2.length - 1; j >= 0; --j) {
                    ha.push(ha2[j]);
                }
            } else {
                // simple len
                ha.push(len);
            }
        }
        let header = source.header = new Uint8Array(ha);

        // Result - complete buffer
        let block = new Uint8Array(header.length + content.length);
        block.set(header, 0);
        block.set(content, header.length);
        return block;
    }




    public static decodeBER(source, offset) {

        // start pos
        let pos = offset || 0;
        let start = pos;
        let tagNumber;
        let tagClass;
        let tagConstructed;
        let content;
        let header;
        let buffer;
        let sub;
        let len;

        if (source.object) {
            // Ready from source
            tagNumber = source.tagNumber;
            tagClass = source.tagClass;
            tagConstructed = source.tagConstructed;
            content = source.content;
            header = source.header;
            buffer = source.object instanceof ArrayBuffer ?
                new Uint8Array(source.object) : null;
            sub = source.object instanceof Array ? source.object : null;
            len = buffer && buffer.length || null;
        } else {
            // Decode header
            let d = source;

            // Read tag
            let buf = d[pos++];
            tagNumber = buf & 0x1f;
            tagClass = buf >> 6;
            tagConstructed = (buf & 0x20) !== 0;
            if (tagNumber === 0x1f) { // long tag
                tagNumber = 0;
                do {
                    if (tagNumber > 0x1fffffffffff80) {
                        throw new Error('Convertor not supported tag number more then (2^53 - 1) at position ' + offset);
                    }
                    buf = d[pos++];
                    tagNumber = (tagNumber << 7) + (buf & 0x7f);
                } while (buf & 0x80);
            }

            // Read len
            buf = d[pos++];
            len = buf & 0x7f;
            if (len !== buf) {
                if (len > 6) { // no reason to use Int10, as it would be a huge buffer anyways
                    throw new Error('Length over 48 bits not supported at position ' + offset);
                }
                if (len === 0) {
                    len = null;
                } else {
                    buf = 0;
                    for (let i = 0; i < len; ++i) {
                        buf = (buf << 8) + d[pos++];
                    }
                    len = buf;
                }
            }

            start = pos;
            sub = null;

            if (tagConstructed) {
                // must have valid content
                sub = [];
                if (len !== null) {
                    // definite length
                    let end = start + len;
                    while (pos < end) {
                        let s = BER.decodeBER(d, pos);
                        sub.push(s);
                        pos += s.header.length + s.content.length;
                    }
                    if (pos !== end) {
                        throw new Error('Content size is not correct for container starting at offset ' + start);
                    }
                } else {
                    // undefined length
                    try {
                        for (; ; ) {
                            let s = BER.decodeBER(d, pos);
                            pos += s.header.length + s.content.length;
                            if (s.tagClass === 0x00 && s.tagNumber === 0x00) {
                                break;
                            }
                            sub.push(s);
                        }
                        len = pos - start;
                    } catch (e) {
                        throw new Error('Exception ' + e + ' while decoding undefined length content at offset ' + start);
                    }
                }
            }

            // Header and content
            header = new Uint8Array(d.buffer, offset, start - offset);
            content = new Uint8Array(d.buffer, start, len);
            buffer = content;
        }

        // Constructed types - check for string concationation
        if (sub !== null && tagClass === 0) {
            let k;
            switch (tagNumber) {
                case 0x03: // BIT_STRING
                    k = 1; // ingnore unused bit for bit string
                // tslint:disable-next-line:no-switch-case-fall-through
                case 0x04: // OCTET_STRING
                case 0x0C: // UTF8String
                case 0x12: // NumericString
                case 0x13: // PrintableString
                case 0x14: // TeletexString
                case 0x15: // VideotexString
                case 0x16: // IA5String
                case 0x19: // GraphicString
                case 0x1A: // VisibleString
                case 0x1B: // GeneralString
                case 0x1C: // UniversalString
                case 0x1E: // BMPString
                    k = k || 0;
                    // Concatination
                    if (sub.length === 0) {
                        throw new Error('No constructed encoding content of string type at offset ' + start);
                    }
                    len = k;
                    for (let i = 0, n = sub.length; i < n; i++) {
                        let s = sub[i];
                        if (s.tagClass !== tagClass || s.tagNumber !== tagNumber || s.tagConstructed) {
                            throw new Error('Invalid constructed encoding of string type at offset ' + start);
                        }
                        len += s.content.length - k;
                    }
                    buffer = new Uint8Array(len);
                    for (let i = 0, n = sub.length, j = k; i < n; i++) {
                        let s = sub[i];
                        if (k > 0) {
                            buffer.set(s.content.subarray(1), j);
                        } else {
                            buffer.set(s.content, j);
                        }
                        j += s.content.length - k;
                    }
                    tagConstructed = false; // follow not required
                    sub = null;
                    break;
            }
        }
        // Primitive types
        let object: any = '';
        if (sub === null) {
            if (len === null) {
                throw new Error('Invalid tag with undefined length at offset ' + start);
            }

            if (tagClass === 0) {
                switch (tagNumber) {
                    case 0x01: // BOOLEAN
                        object = (buffer[0] !== 0);
                        break;
                    case 0x02: // INTEGER
                    case 0x0a: // ENUMIRATED
                        if (len > 6) {
                            object = Int16.encode(buffer);
                        } else {
                            let v = buffer[0];
                            if (buffer[0] > 0x7f) {
                                v = v - 256;
                            }
                            for (let i = 1; i < len; i++) {
                                v = v * 256 + buffer[i];
                            }
                            object = v;
                        }
                        break;
                    case 0x03: // BIT_STRING
                        if (len > 5) { // Content buffer
                            object = new Uint8Array(buffer.subarray(1)).buffer;
                        } else { // Max bit mask only for 32 bit
                            let unusedBit = buffer[0];
                            let skip = unusedBit;
                            let s = [];
                            for (let i = len - 1; i >= 1; --i) {
                                let b = buffer[i];
                                for (let j = skip; j < 8; ++j) {
                                    s.push((b >> j) & 1 ? '1' : '0');
                                }
                                skip = 0;
                            }
                            object = s.reverse().join('');
                        }
                        break;
                    case 0x04: // OCTET_STRING
                        object = new Uint8Array(buffer).buffer;
                        break;
                    //  case 0x05: // NULL
                    case 0x06: // OBJECT_IDENTIFIER
                        let ss = '';
                        let n = 0;
                        let bits = 0;
                        for (let i = 0; i < len; ++i) {
                            let v = buffer[i];
                            n = (n << 7) + (v & 0x7F);
                            bits += 7;
                            if (!(v & 0x80)) { // finished
                                if (ss === '') {
                                    let m = n < 80 ? n < 40 ? 0 : 1 : 2;
                                    ss = m + '.' + (n - m * 40);
                                } else {
                                    ss += '.' + n.toString();
                                }
                                n = 0;
                                bits = 0;
                            }
                        }
                        if (bits > 0) {
                            throw new Error('Incompleted OID at offset ' + start);
                        }
                        object = ss;
                        break;
                    // case 0x07: // ObjectDescriptor
                    // case 0x08: // EXTERNAL
                    // case 0x09: // REAL
                    // case 0x0A: // ENUMERATED
                    // case 0x0B: // EMBEDDED_PDV
                    case 0x10: // SEQUENCE
                    case 0x11: // SET
                        object = [];
                        break;
                    case 0x0C: // UTF8String
                        object = Chars.encode(buffer, 'utf8');
                        break;
                    case 0x12: // NumericString
                    case 0x13: // PrintableString
                    case 0x14: // TeletexString
                    case 0x15: // VideotexString
                    case 0x16: // IA5String
                    case 0x19: // GraphicString
                    case 0x1A: // VisibleString
                    case 0x1B: // GeneralString
                        object = Chars.encode(buffer, 'ascii');
                        break;
                    case 0x1C: // UniversalString
                        object = Chars.encode(buffer, 'utf32');
                        break;
                    case 0x1E: // BMPString
                        object = Chars.encode(buffer, 'utf16');
                        break;
                    case 0x17: // UTCTime
                    case 0x18: // GeneralizedTime
                        let shortYear = tagNumber === 0x17;
                        let sss = Chars.encode(buffer, 'ascii');
                        let m = (shortYear ?
                            // tslint:disable-next-line:max-line-length
                            /^(\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/ :
                            // tslint:disable-next-line:max-line-length
                            /^(\d\d\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/).exec(sss);
                        if (!m) {
                            throw new Error('Unrecognized time format "' + sss + '" at offset ' + start);
                        }
                        if (shortYear) {
                            // Where YY is greater than or equal to 50, the year SHALL be interpreted as 19YY; and
                            // Where YY is less than 50, the year SHALL be interpreted as 20YY
                            // @ts-ignore
                            m[1] = +m[1];
                            // @ts-ignore
                            m[1] += (m[1] < 50) ? 2000 : 1900;
                        }
                        // @ts-ignore
                        let dt = new Date(m[1], +m[2] - 1, +m[3], +(m[4] || '0'), +(m[5] || '0'), +(m[6] || '0'), +(m[7] || '0'));
                        let tz = dt.getTimezoneOffset();
                        if (m[8] || tagNumber === 0x17) {
                            if (m[8].toUpperCase() !== 'Z' && m[9]) {
                                tz = tz + parseInt(m[9], 10);
                            }
                            dt.setMinutes(dt.getMinutes() - tz);
                        }
                        dt.original = sss;
                        object = dt;
                        break;
                }
            } else { // OCTET_STRING
                object = new Uint8Array(buffer).buffer;
            }
        } else {
            object = sub;
        }

        // result
        return {
            tagConstructed,
            tagClass,
            tagNumber,
            header,
            content,
            object
        };
    }

}

