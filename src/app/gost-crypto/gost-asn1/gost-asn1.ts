import {PEM} from '../gost-coding/gost-coding';
import {Asn1ServiceFunctions} from './Asn1ServiceFunctions';
import {SInt} from './SInt';
import {BERElement, DERElement} from 'asn1-ts';
import {BERtypes} from './structure/BERTypes';
import {PrivateKeyInfo} from './private-keys-algs/private-key-info';
import {PrivateKeyAlgorithm} from './private-keys-algs/private-key-algorithm';
import {GostSecurity} from '../gost-security/gost-security';
import { GostKeyContainerName, GostKeyContainer, GostPrivateKeys, GostPrivateMasks } from './cp/CP';
import {SubjectPublicKeyInfo, TBSCertificate, Certificate, Name} from './certificate/Certificate';

/**
 * ASN.1 syntax definitions
 *
 */


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

    GostPrivateKeyInfo = GostPrivateKeyInfo;
    GostSubjectPublicKeyInfo = GostSubjectPublicKeyInfo;
    /*
    header - container header @link GostASN1.GostKeyContainer</li>
    name - container name @link GostASN1.GostKeyContainerName</li>
    primary - private keys data @link GostASN1.GostPrivateKeys</li>
    masks - private key masks @link GostASN1.GostPrivateMasks</li>
    primary2 - reserve of private keys data @link GostASN1.GostPrivateKeys</li>
    masks2 - reserve of private key masks @link GostASN1.GostPrivateMasks</li>
    * */

    GostKeyContainer = GostKeyContainer;
    GostKeyContainerName = GostKeyContainerName;
    GostPrivateKeys = new GostPrivateKeys(undefined);
    GostPrivateMasks = new GostPrivateMasks(undefined, undefined, undefined);

    ViPNetInfo: ViPNetInfo;
    GostSignature: GostSignature;
    GostEncryptedKey: GostEncryptedKey;
    GostWrappedPrivateKey: GostWrappedPrivateKey;
    PrivateKeyInfo = new PrivateKeyInfo(undefined, undefined, undefined);
    EncryptedPrivateKeyInfo: EncryptedPrivateKeyInfo;
    SubjectPublicKeyInfo = new  SubjectPublicKeyInfo();
    TBSCertificate = new TBSCertificate();
    Certificate = new Certificate();
    CertificationRequestInfo: CertificationRequestInfo;
    CertificationRequest: CertificationRequest;
    TBSCertList: TBSCertList;
    CertificateList: CertificateList
    AttributeCertificateInfo: AttributeCertificateInfo;
    AttributeCertificate: AttributeCertificate;
    SignedAttributes: SignedAttributes;
    UnsignedAttributes: UnsignedAttributes;
    ContentInfo: ContentInfo;
    SafeContents: SafeContents;
    AuthenticatedSafe: AuthenticatedSafe;
    PFX: PFX;
    PKIData: PKIData;
    PKIResponse: PKIResponse;
    Name = new Name(undefined);



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
class GostPrivateKeyInfo {
}

class GostSubjectPublicKeyInfo {
}
