import {BER, Chars, Hex, PEM} from '../gost-coding/gost-coding';
import {AlgorithmDto} from '../../dto/algorithm-dto';
import {GostSecurity} from '../gost-security/gost-security';
import {GostRandom} from '../gost-random/gost-random';
import {GostSubtleCrypto} from '../gost-subtle/gost-subtle-crypto';
import {GostEngine} from '../gost-engine/gost-engine';
import {GostCrypto} from '../gost-crypto/gost-crypto';
import {Asn1ServiceFunctions} from './Asn1ServiceFunctions';
import {SInt} from './SInt';
import {ARRAY_OF, ASN1Object, BIT_STRING, OCTET_STRING, PRIMITIVE, PRIMITIVE_CODE} from './structure/ASN1Object';

/**
 * ASN.1 syntax definitions
 *
 */

export class GostAsn1 {
    ANY = new ASN1Object();
    BOOLEAN = new PRIMITIVE(0x01);
    IA5String = new PRIMITIVE(0x16);
    NumericString = new PRIMITIVE(0x12);
    PrintableString = new PRIMITIVE(0x13);
    TeletexString = new PRIMITIVE(0x14);
    UTF8String = new PRIMITIVE(0x0c);
    UTCTime = new PRIMITIVE(0x17);
    GeneralizedTime = new PRIMITIVE(0x18);
    UniversalString = new PRIMITIVE(0x1C);
    BMPString = new PRIMITIVE(0x1e);
    NULL = new PRIMITIVE(0x05);


    INTEGER = new PRIMITIVE_CODE(0x02);
    ENUMERATED = new PRIMITIVE_CODE(0x0a);

    OCTET_STRING = new OCTET_STRING();
    BIT_STRING = new BIT_STRING();


    SEQUENCE_OF = new ARRAY_OF(0x10);
    SET_OF = new ARRAY_OF(0x11);
    SET_OF_SINGLE;
    /**
     * Gost PrivateKey info encoder
     *
     * @memberOf GostASN1
     */
    GostPrivateKeyInfo: GostPrivateKeyInfo;
    /**
     * Gost subject PublicKey info encoder
     *
     * @memberOf GostASN1
     */
    GostSubjectPublicKeyInfo: GostSubjectPublicKeyInfo;
    /**
     * CryptoPro key container header
     *
     * @memberOf GostASN1
     */
    GostKeyContainer: GostKeyContainer;
    /**
     * CryptoPro key container name
     *
     * @memberOf GostASN1
     */
    GostKeyContainerName: GostKeyContainerName;
    /**
     * CryptoPro encrypted PrivateKey for key containers
     *
     * @memberOf GostASN1
     */
    GostPrivateKeys: GostPrivateKeys;
    /**
     * CryptoPro PrivateKey masks for key containers
     *
     * @memberOf GostASN1
     */
    GostPrivateMasks: GostPrivateMasks;
    /**
     * ViPNet key container
     *
     * @memberOf GostASN1
     */
    ViPNetInfo: ViPNetInfo;
    /**
     * Gost Signature encoders
     *
     * @memberOf GostASN1
     */
    GostSignature: GostSignature;
    /**
     * Gost Encrypted key encoder for CMS
     *
     * @memberOf GostASN1
     */
    GostEncryptedKey: GostEncryptedKey;
    /**
     * SignalCom wrapped PrivateKey
     *
     * @memberOf GostASN1
     */
    GostWrappedPrivateKey: GostWrappedPrivateKey;
    /**
     * PKCS#8 PrivateKey info
     *
     * @memberOf GostASN1
     */
    PrivateKeyInfo: PrivateKeyInfo;
    /**
     * PKCS#8 encrypted PrivateKey info
     *
     * @memberOf GostASN1
     */
    EncryptedPrivateKeyInfo: EncryptedPrivateKeyInfo;
    /**
     * X.509 subject PublicKey info
     *
     * @memberOf GostASN1
     */
    SubjectPublicKeyInfo: SubjectPublicKeyInfo;
    /**
     * X.509 To be signed Certificate
     *
     * @memberOf GostASN1
     */
    TBSCertificate: TBSCertificate;
    /**
     * X.509 Certificate
     *
     * @memberOf GostASN1
     */
    Certificate: Certificate;
    /**
     * PKCS#10 Certification request definition
     *
     * @memberOf GostASN1
     */
    CertificationRequestInfo: CertificationRequestInfo;
    /**
     * PKCS#10 Certification request
     *
     * @memberOf GostASN1
     */
    CertificationRequest: CertificationRequest;
    /**
     * X.509 To be signed CRL
     *
     * @memberOf GostASN1
     */
    TBSCertList: TBSCertList;
    /**
     * X.509 CRL
     *
     * @memberOf GostASN1
     */
    CertificateList: CertificateList;
    /**
     * X.509 Attribute Certificate definition
     *
     * @memberOf GostASN1
     */
    AttributeCertificateInfo: AttributeCertificateInfo;
    /**
     * X.509 Attribute Certificate
     *
     * @memberOf GostASN1
     */
    AttributeCertificate: AttributeCertificate;
    /**
     * CMS Signed Attributes
     *
     * @memberOf GostASN1
     */
    SignedAttributes: SignedAttributes;
    /**
     * CMS Unsigned Attributes
     *
     * @memberOf GostASN1
     */
    UnsignedAttributes: UnsignedAttributes;
    /**
     * CMS Content definition
     *
     * @memberOf GostASN1
     */
    ContentInfo: ContentInfo;
    /**
     * PKCS#12 Safe Contents
     *
     * @memberOf GostASN1
     */
    SafeContents: SafeContents;
    /**
     * PKCS#12 Authenticated Safe
     *
     * @memberOf GostASN1
     */
    AuthenticatedSafe: AuthenticatedSafe;
    /**
     * PKCS#12 Personal Information Exchange (PFX)
     *
     * @memberOf GostASN1
     */
    PFX: PFX;
    /**
     * PKI Request
     *
     * @memberOf GostASN1
     */
    PKIData: PKIData;
    /**
     * PKI Response
     *
     * @memberOf GostASN1
     */
    PKIResponse: PKIResponse;


    /*
 * Base ASN.1 types and definitions
 *
 */ // <editor-fold defaultstate="collapsed">

    // Encode object primitive
    static encode(format, object, tagNumber, tagClass, tagConstructed, uniformTitle) {
        Asn1ServiceFunctions.assert(object === undefined);
        let source = {
            tagNumber,
            tagClass: tagClass || 0x00,
            tagConstructed: tagConstructed || false,
            object
        };
        // Output format
        format = format || 'DER';
        if (format === 'DER' || format === 'CER')
            source = SInt.encode(source, format);
        if (format === 'PEM')
            source = SInt.encode(source, uniformTitle);
        return source;
    }

    // Decode object primitive
    static decode(source, tagNumber, tagClass, tagConstructed, uniformTitle) {
        Asn1ServiceFunctions.assert(source === undefined);

        // Decode PEM
        if (typeof source === 'string')
            source = SInt.decode(source, uniformTitle, false);
        // Decode binary data
        if (source instanceof ArrayBuffer) {
            try {
                source = SInt.decode(SInt.encode(source, undefined), uniformTitle, true);
            } catch (e) {
                source = SInt.decode(source, undefined, undefined);
            }
        }

        tagClass = tagClass || 0;
        tagConstructed = tagConstructed || false;
        // Restore context implicit formats
        if (source.tagNumber === undefined) {
            source = this.encode(true, source.object, tagNumber, tagClass,
                source.object instanceof Array, undefined);
            source = SInt.decode(source, undefined, undefined);
        }

        // Check format
        Asn1ServiceFunctions.assert(source.tagClass !== tagClass ||
            source.tagNumber !== tagNumber ||
            source.tagConstructed !== tagConstructed);
        // Clone value define from redefine original
        if (tagClass === 0 && tagNumber === 0x05)
            return null;
        else
            return source.object;
    }
}
class GostPrivateKeyInfo {
}

class GostSubjectPublicKeyInfo {
}

class GostKeyContainer {
}

class GostKeyContainerName {
}

class GostPrivateKeys {
}

class GostPrivateMasks {
}

class ViPNetInfo {
}

class GostSignature {
}

class GostEncryptedKey {
}

class GostWrappedPrivateKey {
}

class PrivateKeyInfo {
}

class CertificationRequestInfo {
}

class Certificate {
}

class EncryptedPrivateKeyInfo {
}

class SubjectPublicKeyInfo {
}

class TBSCertificate {
}

class CertificationRequest {
}

class TBSCertList {
}

class CertificateList {
}

class AttributeCertificateInfo {
}

class AttributeCertificate {
}

class SignedAttributes {
}

class UnsignedAttributes {
}

class ContentInfo {
}

class PKIResponse {
}

class PKIData {
}

class PFX {
}

class AuthenticatedSafe {
}

class SafeContents {
}



/*
export class GostAsn1 {
    GostSignature: any;
}*/
/*

export class GostAsn1 {

    subtle = new GostSubtleCrypto(new GostCrypto(), new GostEngine());

    gostCrypto: GostSecurity = new GostSecurity();

    // Security parameters
    algorithms = this.gostCrypto.algorithms;
    names = this.gostCrypto.names;
    identifiers = this.gostCrypto.identifiers;
    attributes = this.gostCrypto.attributes;
    parameters = this.gostCrypto.parameters;
    SInt = new SInt(this);
    GostSignature: any;

    constructor() {

    }

    // Expand javascript object
    expand(args) { // TODO to remove
        const r = {};
        for (let i = 0, n = args.length; i < n; i++) {
            const item = args[i];
            if (typeof item === 'object') {
                // tslint:disable-next-line:forin
                for (const name in item) {
                    r[name] = item[name];
                }
            }
        }
        return r;
    }

    // Swap bytes in buffer
    swapBytes(src) {
        if (src instanceof ArrayBuffer) {
            src = new Uint8Array(src);
        }
        const dst = new Uint8Array(src.length);
        for (let i = 0, n = src.length; i < n; i++) {
            dst[n - i - 1] = src[i];
        }
        return dst.buffer;
    }

    isBinary(value) {
        return value instanceof ArrayBuffer || value.buffer instanceof ArrayBuffer;
    }

    // Left pad zero
    lpad(n, width) {
        return n.length >= width ? n : new Array(width - n.length + 1).join('0') + n;
    }

    // Nearest power 2
    npw2(n) {
        return n <= 2 ? n : n <= 4 ? 4 : n <= 8 ? 8 : n <= 16 ? 16 :
            n <= 32 ? 32 : n <= 64 ? 64 : n <= 128 ? 128 : n <= 256 ? 256 :
                n < 512 ? 512 : n < 1024 ? 1024 : undefined;
    }

    // Assert invalid message
    assert(value) {
        if (value) {
            throw Error('Invalid format');
        }
    }

    defineProperty(object, name, descriptor, enumerable) { // TODO to remove
        if (typeof descriptor !== 'object') {
            descriptor = {value: descriptor};
        }
        if (enumerable !== undefined) {
            descriptor.enumerable = enumerable;
        }
        Object.defineProperty(object, name, descriptor);
    }

    defineProperties(object, properties, enumerable) { // TODO to remove
        // tslint:disable-next-line:forin
        for (const name in properties) {
            this.defineProperty(object, name, properties[name], enumerable);
        }
    }

    getOwnPropertyDescriptor(object, name) { // TODO to remove
        return Object.getOwnPropertyDescriptor(object, name);
    }
    encode(format, object, tagNumber, tagClass, tagConstructed, uniformTitle) {
        this.assert(object === undefined);
        let source: { tagNumber: any; tagClass: any; tagConstructed: any; object: any } | string = {
            tagNumber,
            tagClass: tagClass || 0x00,
            tagConstructed: tagConstructed || false,
            object
        };
        // Output format
        format = format || 'DER';
        if (format === 'DER' || format === 'CER') {
            source = BER.encode(source, format, undefined);
        }
        if (format === 'PEM') {
            source = PEM.encode(source, uniformTitle);
        }
        return source;
    }

    // Decode object primitive
    decode(source, tagNumber, tagClass, tagConstructed, uniformTitle) {
        this.assert(source === undefined);

        // Decode PEM
        if (typeof source === 'string') {
            source = PEM.decode(source, uniformTitle, false, undefined);
        }
        // Decode binary data
        if (source instanceof ArrayBuffer) {
            try {
                source = PEM.decode(Chars.encode(source, undefined), uniformTitle, true, undefined);
            } catch (e) {
                source = BER.decode(source);
            }
        }

        tagClass = tagClass || 0;
        tagConstructed = tagConstructed || false;
        // Restore context implicit formats
        if (source.tagNumber === undefined) {
            source = this.encode(true, source.object, tagNumber, tagClass,
                source.object instanceof Array, undefined);
            source = BER.decode(source);
        }

        // Check format
        this.assert(source.tagClass !== tagClass ||
            source.tagNumber !== tagNumber ||
            source.tagConstructed !== tagConstructed);
        // Clone value define from redefine original
        if (tagClass === 0 && tagNumber === 0x05) {
            return null;
        } else {
            return source.object;
        }
    }

    // Create class based on super
    extend(Super, Class, propertiesObject, propertiesClass) { // TODO to remove
        // If constructor not defined
        if (typeof Class !== 'function') {
            propertiesClass = propertiesObject;
            propertiesObject = Class;
            Class = () => {
                Super.apply(this, arguments);
            };
        }
        // Create prototype properties
        Class.prototype = Object.create(Super.prototype, {
            constructor: {
                value: Class
            },
            superclass: {
                value: Super.prototype
            }
        });
        if (propertiesObject) {
            this.defineProperties(Class.prototype, propertiesObject, undefined);
        }
        // Inherites super class properties
        if (Super !== Object) {
            // tslint:disable-next-line:forin
            for (const name in Super) {
                Class[name] = Super[name];
            }
        }
        Class.super = Super;
        if (propertiesClass) {
            this.defineProperties(Class, propertiesClass, true);
        }
        return Class;
    }

    getSeed(length) {
        const seed = new Uint8Array(length);
        GostRandom.getRandomValues(seed);
        return seed.buffer;
    }

    // Self resolver
    call(callback) {
        try {
            callback();
        } catch (e) {
        }
    }

    buffer(d) {
        if (d instanceof ArrayBuffer) {
            return d;
        } else if (d && d.buffer && d.buffer instanceof ArrayBuffer) {
            return d.byteOffset === 0 && d.byteLength === d.buffer.byteLength ?
                d.buffer : new Uint8Array(new Uint8Array(d, d.byteOffset, d.byteLength)).buffer;
        } else {
            throw new Error('CryptoOperationData required');
        }
    }

    now(n) {
        const date = new Date();
        if (n) {
            date.setDate(date.getDate() + n);
        }
        return date;
    }

    today(n) {
        const date = this.now(n);
        date.setHours(0, 0, 0, 0);
        return date;
    }

    equalBuffers(r1, r2) {
        const s1 = new Uint8Array(r1);
        const s2 = new Uint8Array(r2);
        if (s1.length !== s2.length) {
            return false;
        }
        for (let i = 0, n = s1.length; i < n; i++) {
            if (s1[i] !== s2[i]) {
                return false;
            }
        }
        return true;
    }

    generateUUID() {
        const r = new Uint8Array(this.getSeed(16));
        let s = '';
        for (let i = 0; i < 16; i++) {
            s += ('00' + r[i].toString(16)).slice(-2);
        }
        return s.substr(0, 8) + '-' + s.substr(8, 4) + '-4' + s.substr(13, 3) +
            '-9' + s.substr(17, 3) + '-' + s.substr(20, 12);
    }

    get32(buffer, offset) {
        const r = new Uint8Array(buffer, offset, 4);
        return (r[3] << 24) | (r[2] << 16) | (r[1] << 8) | r[0];
    }
    set32(buffer, offset, int) {
        const r = new Uint8Array(buffer, offset, 4);
        r[3] = int >>> 24;
        r[2] = int >>> 16 & 0xff;
        r[1] = int >>> 8 & 0xff;
        r[0] = int & 0xff;
        return r;
    }

    saltSize(algorithm) {
        switch (algorithm.id) {
            case 'pbeWithSHAAnd40BitRC2-CBC':
            case 'pbeWithSHAAnd128BitRC2-CBC':
                return 8;
            case 'pbeUnknownGost':
                return 16;
            case 'sha1':
                return 20;
            default:
                return 32;
        }
    }

    passwordData(derivation, password) {
        if (!password) {
            return new ArrayBuffer(0);
        }
        if (derivation.name.indexOf('CPKDF') >= 0) {
            // CryptoPro store password
            const r = [];
            for (let i = 0; i < password.length; i++) {
                const c = password.charCodeAt(i);
                r.push(c & 0xff);
                r.push(c >>> 8 & 0xff);
                r.push(0);
                r.push(0);
            }
            return new Uint8Array(r).buffer;
        } else if (derivation.name.indexOf('PFXKDF') >= 0) {
            // PKCS#12 unicode password
            return Chars.decode(password + '\0', 'unicode');
        } else {
            // PKCS#5 password mode
            return Chars.decode(password, 'utf8');
        }
    }
}
class GostKeys {
    private privateKeyAlgorithm: any;

    getPrivateKey()
    {
        let keyUsages = (this.privateKeyAlgorithm.id === 'rsaEncryption') ? ['sign'] :
            ['sign', 'deriveKey', 'deriveBits'];
        return this.asn1.subtle.importKey('pkcs8', this.encode(), this.privateKeyAlgorithm, 'true', keyUsages);
    }
    setPrivateKey(privateKey)
    {
        let self = this;
        return this.asn1.subtle.exportKey('pkcs8', privateKey).then((keyInfo) => {
            this.asn1.PrivateKeyInfo.call(self, keyInfo);
            return self;
        });
    }
    generate(req, keyAlgorithm)
    {
        let self = this;
        return new Promise(call).then(() => {
            if (!(req instanceof cert.Request))
                req = new cert.Request(req);
            // Generate request
            return req.generate(keyAlgorithm);
        }).then((key) => {
            this.asn1.PrivateKeyInfo.call(self, key);
            return req;
        });
    } // </editor-fold>

    constructor(private asn1: GostAsn1) {
    }

    options = {// <editor-fold defaultstate="collapsed">
        providerName: 'CP-01',
        days: 7305 // </editor-fold>
    };

    PKCS8(keyInfo) {
        this.asn1.PrivateKeyInfo(keyInfo);
    }

    PrivateKeyInfo;
}

class ASN1Object {

    // Call set method for a class property
    _set(Class, propName, value) {
        Class.property(propName).set(value);
    }

    // Call get method for a class property
    _get(Class, propName) {
        return Class.property(propName).get.call(this);
    }

    // Call method for a class
    _call(Class, methodName, args) {
        return Class.method(methodName).apply(this, args);
    }

    hasProperty(propName) {
        return this.hasOwnProperty(propName) ||
            !!this.constructor.property(propName);
    }

    encode() {
        return this.object;
    }
    decode(source) {
        return new this(source);
    }

    // Find ingerited property
    property(propName) {
        let proto = this.prototype;
        while (proto) {
            const descriptor = this.getOwnPropertyDescriptor(proto, propName);
            if (descriptor) {
                return descriptor;
            } else {
                proto = proto.superclass;
            }
        }
    }

    // Find method
    method(methodName) {
        let proto = this.prototype;
        while (proto) {
            if (proto[methodName]) {
                return proto[methodName];
            } else {
                proto = proto.superclass;
            }
        }
    }
}
class SInt {

    constructor(private gostAsn1: GostAsn1) {
    }

    encode(value, endian) {
        return '0x' + Hex.encode(value, endian);
    }

    decode(value, endian, len) {
        if (typeof value === 'number') {
            value = value.toString(16);
        }
        const s = value.replace('0x', '');
        len = len || this.gostAsn1.npw2(s.length);
        return Hex.decode(this.gostAsn1.lpad(s, len), endian);
    }
}

class PrivateKeyInfo {

}
*/
