import {BER, Chars, Hex, PEM} from '../gost-coding/gost-coding';

import {Asn1ServiceFunctions} from './Asn1ServiceFunctions';
import {SInt} from './SInt';
import {BERElement, ObjectIdentifier} from 'asn1-ts';
import {BERtypes} from '../gost-viewer/BERTypes';

/**
 * ASN.1 syntax definitions
 *
 */
class GostKeyContainerName {
    containerName: string; // ia5string
    extElem1: any; // wtf
    constructor(containerName: string, extElem1: any) {
        this.containerName = containerName;
        this.extElem1 = extElem1;
    }

    public static decode(value: ArrayBuffer) {
        let encodedData: Uint8Array = new Uint8Array(value);
        let berElement: BERElement = new BERElement();
        berElement.fromBytes(encodedData);
        let containerName;
        let extElem1;
        if (berElement.sequence[0]) {
            containerName = berElement.sequence[0].ia5String;
        }
        if (berElement.sequence[1]) {
            extElem1 = berElement.sequence[0].toBytes();
        }
        return new GostKeyContainerName(containerName, extElem1);
    }

    public static encode(value: GostKeyContainerName): ArrayBuffer {
        let toReturn: BERElement = new BERElement();

        let containerName: BERElement = new BERElement();
        containerName.ia5String = value.containerName;
        toReturn.sequence.push(containerName);

        let extElem1: BERElement = new BERElement();
        extElem1.fromBytes(value.extElem1);
        toReturn.sequence.push(extElem1);

        return toReturn.toBytes();
    }
}


export class PrivateKeyInfo {
    version: number;
    privateKeyAlgorithm: PrivateKeyAlgorithm;
    privateKey: Uint8Array;


    constructor(version: number, privateKeyAlgorithm: PrivateKeyAlgorithm, privateKey: Uint8Array) {
        this.version = version;
        this.privateKeyAlgorithm = privateKeyAlgorithm;
        this.privateKey = privateKey;
    }

    public static decode(value: ArrayBuffer) {
        let encodedData: Uint8Array = new Uint8Array(value);
        let berElement: BERElement = new BERElement();
        berElement.fromBytes(encodedData);


        let version;
        let privateKeyAlgorithm;
        let privateKey;
        if (berElement.sequence[0]) {
            version = berElement.sequence[0].integer;
        }
        if (berElement.sequence[1]) {
            let objectIdentifier = berElement.sequence[1].sequence[0].objectIdentifier;
            switch (objectIdentifier.dotDelimitedNotation) {
                case '1.2.840.113549.1.1.1':
                    privateKeyAlgorithm = new PrivateKeyAlgorithm('RSASSA-PKCS1-v1_5',
                        {
                            name: 'SHA-256'
                        },
                        'rsaEncryption');
                    break;
                default:
                    throw new Error('Unknown Private Key OID ' + objectIdentifier.dotDelimitedNotation);
            }

            // berElement.sequence[1].sequence[1].tagNumber = BERtypes.NULL;
        }
        if (berElement.sequence[2]) {
            privateKey = berElement.sequence[2].octetString; // там какая-то фигня, кладём как есть
        }
        return new PrivateKeyInfo(version, privateKeyAlgorithm, privateKey);
    }


    public static encode(value: PrivateKeyInfo): ArrayBuffer {
        let toReturn: BERElement = new BERElement();

        let version: BERElement = new BERElement();
        version.integer = value.version;
        toReturn.sequence.push(version);

        let privateKeyAlgorithm: BERElement = new BERElement();
        privateKeyAlgorithm.fromBytes(PrivateKeyAlgorithm.encode(value.privateKeyAlgorithm));
        toReturn.sequence.push(version);

        let privateKey: BERElement = new BERElement();
        privateKey.fromBytes(value.privateKey);
        toReturn.sequence.push(privateKey);

        return toReturn.toBytes();
    }
}

export class PrivateKeyAlgorithm {
    name: string;
    hash: any;
    id: string;

    constructor(name: string, hash: any, id: string) {
        this.name = name;
        this.hash = hash;
        this.id = id;
    }

    /*    public static decode(value: ArrayBuffer) {
            let encodedData: Uint8Array = new Uint8Array(value);
            let berElement: BERElement = new BERElement();
            berElement.fromBytes(encodedData);

            let name;
            let hash;
            let id;
            if (berElement.sequence[0]) {
                name = berElement.sequence[0].ia5String;
            }
            if (berElement.sequence[1]) {
                extElem1 = berElement.sequence[0].toBytes();
            }
            return new PrivateKeyAlgorithm(containerName, extElem1);
        }*/

    public static encode(value: PrivateKeyAlgorithm): Uint8Array {
        let toReturn: BERElement = new BERElement();
        let privateKeyAlgorithm: BERElement;

        if (value.name === 'RSASSA-PKCS1-v1_5' && value.id === 'rsaEncryption') {
            privateKeyAlgorithm  = new BERElement(); // 1.2.840.113549.1.1.1
            privateKeyAlgorithm.objectIdentifier = new ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]);
            toReturn.sequence.push(privateKeyAlgorithm);
            toReturn.sequence.push(null);
        }

        return toReturn.toBytes();
    }

}


export class GostAsn1 {
    /*  KeyAlgorithmIdentifier = AlgorithmIdentifier({
          ecdsa: ECDHKeyAlgorithm,
          noSignature: AlgorithmWithNullParam,
          rsaEncryption: AlgorithmWithNullParam,
          'id-sc-gostR3410-2001': ECDHKeyAlgorithm,
          'id-GostR3410-2001': GostKeyAlgorithm,
          'id-GostR3410-94': GostKeyAlgorithm,
          'id-GostR3410-2001DH': GostKeyAlgorithm,
          'id-GostR3410-94DH': GostKeyAlgorithm,
          'id-tc26-gost3410-12-256': GostKeyAlgorithm,
          'id-tc26-gost3410-12-512': GostKeyAlgorithm,
          'id-tc26-agreement-gost-3410-12-256': GostKeyAlgorithm,
          'id-tc26-agreement-gost-3410-12-512': GostKeyAlgorithm,
          'id-sc-gost28147-gfb': AlgorithmWithNoParam,
          'id-Gost28147-89': AlgorithmWithNoParam
      });

      SignatureAlgorithmIdentifier = AlgorithmIdentifier({
          noSignature: AlgorithmWithNullParam,
          rsaEncryption: AlgorithmWithNullParam,
          sha1withRSAEncryption: AlgorithmWithNullParam,
          sha256withRSAEncryption: AlgorithmWithNullParam,
          sha384withRSAEncryption: AlgorithmWithNullParam,
          sha512withRSAEncryption: AlgorithmWithNullParam,
          ecdsa: AlgorithmWithNoParam,
          'ecdsa-with-SHA1': AlgorithmWithNoParam,
          'ecdsa-with-SHA256': AlgorithmWithNoParam,
          'ecdsa-with-SHA384': AlgorithmWithNoParam,
          'ecdsa-with-SHA512': AlgorithmWithNoParam,
          'id-GostR3410-94': AlgorithmWithNullParam,
          'id-GostR3410-2001': AlgorithmWithNullParam,
          'id-GostR3411-94-with-GostR3410-2001': AlgorithmWithNoParam,
          'id-GostR3411-94-with-GostR3410-94': AlgorithmWithNoParam,
          'id-tc26-gost3410-12-256': AlgorithmWithNullParam,
          'id-tc26-gost3410-12-512': AlgorithmWithNullParam,
          'id-tc26-signwithdigest-gost3410-12-94': AlgorithmWithNoParam,
          'id-tc26-signwithdigest-gost3410-12-256': AlgorithmWithNoParam,
          'id-tc26-signwithdigest-gost3410-12-512': AlgorithmWithNoParam,
          'id-sc-gostR3410-94': AlgorithmWithNullParam,
          'id-sc-gostR3410-2001': AlgorithmWithNullParam,
          'id-sc-gostR3411-94-with-gostR3410-94': AlgorithmWithNullParam,
          'id-sc-gostR3411-94-with-gostR3410-2001': AlgorithmWithNullParam
      });

     DigestAlgorithmIdentifier = AlgorithmIdentifier({
          sha1: AlgorithmWithNoParam,
          sha256: AlgorithmWithNullParam,
          sha384: AlgorithmWithNullParam,
          sha512: AlgorithmWithNullParam,
          'id-GostR3411-94': Gost341194DigestAlgorithm,
          'id-tc26-gost3411-94': Gost341194DigestAlgorithm,
          'id-tc26-gost3411-12-256': AlgorithmWithNullParam,
          'id-tc26-gost3411-12-512': AlgorithmWithNullParam,
          'id-sc-gostR3411-94': AlgorithmWithNoParam});*/

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
    GostKeyContainerName = GostKeyContainerName;
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
    PrivateKeyInfo = PrivateKeyInfo;
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
        if (format === 'DER' || format === 'CER') {
            source = SInt.encode(source, format);
        }
        if (format === 'PEM') {
            source = SInt.encode(source, uniformTitle);
        }
        return source;
    }

    // Decode object primitive
    static decode(source, tagNumber, tagClass, tagConstructed, uniformTitle) {
        Asn1ServiceFunctions.assert(source === undefined);

        // Decode PEM
        if (typeof source === 'string') {
            source = SInt.decode(source, uniformTitle, false);
        }
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
        if (tagClass === 0 && tagNumber === 0x05) {
            return null;
        } else {
            return source.object;
        }
    }
}

class GostPrivateKeyInfo {
}

class GostSubjectPublicKeyInfo {
}

class GostKeyContainer {
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


class CertificationRequestInfo {
}

class Certificate {
}

class EncryptedPrivateKeyInfo {
    // version: GostAsn1.INTEGER;
    // privateKeyAlgorithm: GostAsn1['KeyAlgorithmIdentifier'];
    // privateKey: GostAsn1['ANY'];
    // attributes: GostAsn1['OPTIONAL'];

    /*    decode(value) {
            return {
                version: 0,
                privateKeyAlgorithm: value.algorithm,
                privateKey: value.buffer
            } as EncryptedPrivateKeyInfo;
        }*/

    encode(value) {

    }
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
