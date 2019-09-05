import {PrivateKeyAlgorithm} from '../private-keys-algs/private-key-algorithm';
import {DERElement, ObjectIdentifier as OID} from 'asn1-ts';
import {BERtypes, getValueFromDer} from '../structure/BERTypes';
import {DerFunctions} from '../DerFunctions';


export class Certificate {
    tbsCertificate: TBSCertificate;
    signatureAlgorithm: PrivateKeyAlgorithm;
    signatureValue: ArrayBuffer; // BitString

    public decode(value: ArrayBuffer) {
        throw Error('Unsuported \n' + JSON.stringify(value));
    }

    public encode(value: Certificate): ArrayBuffer {
        throw Error('Unsuported \n' + JSON.stringify(value));
    }
}

export class SubjectPublicKeyInfo {

    public decode(value: ArrayBuffer) {
        throw Error('Unsuported \n' + JSON.stringify(value));
    }

    public encode(value: SubjectPublicKeyInfo): ArrayBuffer {
        throw Error('Unsuported \n' + JSON.stringify(value));
    }
}

export class Meta {
    value: boolean | null | number | undefined | string | number | ArrayBuffer | DERElement[] | OID;
    tagNumber: number;

    constructor(value: any, tagNumber: number) {
        this.value = value;
        this.tagNumber = tagNumber;
    }
}

export class Name extends Map<string, Meta> {

    constructor(input: Map<string, Meta>) {
        super();
        if (input) {
            input.forEach((v: Meta, k: string) => {
                this.set(k, v);
            });
        }
    }

    public decode(value: ArrayBuffer): Name {
        let name: DERElement = new DERElement();
        name.fromBytes(new Uint8Array(value));
        for (const derElement of name.sequence) {
            let oid: string = derElement.set[0].sequence[0].objectIdentifier.toString();
            let content = getValueFromDer(derElement.set[0].sequence[0]);
            this.set(oid, new Meta(content, derElement.set[0].sequence[1].tagNumber));
        }
        throw Error('Unsuported \n' + JSON.stringify(value));
    }

    public encode(value: Name): ArrayBuffer {

        return this.toElement(value).toBytes();
    }

    public toElement(value: Name): DERElement {

        let sec: DERElement[] = [];
        value.forEach((v: Meta, k: string) => {
            if (!v.tagNumber) {
                v.tagNumber = BERtypes.UTF8String; // FIXME временное решение, необходимо ставить тип по ситуации.
            }
            sec.push(DerFunctions.createSet(
                [DerFunctions.createSequence(
                    [DerFunctions.convertOid(k), DerFunctions.createByTag(v.value, v.tagNumber)])]));
        });

        let toReturn = new DERElement();
        toReturn.tagNumber = BERtypes.SEQUENCE;
        toReturn.sequence = sec;
        toReturn.tagClass = 0;
        return toReturn;
    }
}

export class Validity {
    notBefore: Date;
    notAfter: Date;

    constructor(notBefore: Date, notAfter: Date) {
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    public decode(value: ArrayBuffer): Validity {
        let dERElement: DERElement = new DERElement();
        dERElement.fromBytes(new Uint8Array(value));
        return new Validity(dERElement.sequence[0].utcTime, dERElement.sequence[1].utcTime);
    }

    public encode(value: Validity): ArrayBuffer {
        return DerFunctions.createSequence([
            DerFunctions.createByTag(value.notBefore, BERtypes.UTCTime),
            DerFunctions.createByTag(value.notAfter, BERtypes.UTCTime)
        ]).toBytes();
    }
}

export class CertExtensions {
    public decode(value: ArrayBuffer): CertExtensions {
        throw Error('Unsuported \n' + JSON.stringify(value));
    }

    public encode(value: CertExtensions): ArrayBuffer {
        throw Error('Unsuported \n' + JSON.stringify(value));
    }
}

export class TBSCertificate {
    version: number;
    serialNumber: number;
    signature: PrivateKeyAlgorithm;
    issuer: Name;
    validity: Validity;
    subject: Name;
    subjectPublicKeyInfo: SubjectPublicKeyInfo;
    // issuerUniqueID: OPTIONAL(CTX(1, IMPLICIT(UniqueIdentifier)));
    // subjectUniqueID: OPTIONAL(CTX(2, IMPLICIT(UniqueIdentifier)));
    extensions: CertExtensions;

    public decode(value: ArrayBuffer) {
        throw Error('Unsuported \n' + JSON.stringify(value));
    }

    public encode(tBSCertificate: TBSCertificate): ArrayBuffer {
        return DerFunctions.createSequence([
            DerFunctions.createVersion(tBSCertificate.version),
            DerFunctions.createInteger(tBSCertificate.serialNumber),
            DerFunctions.fromBytes(tBSCertificate.signature.encode(tBSCertificate.signature)),
            DerFunctions.fromBytes(tBSCertificate.issuer.encode(tBSCertificate.issuer)),
            DerFunctions.fromBytes(tBSCertificate.validity.encode(tBSCertificate.validity)),
            DerFunctions.fromBytes(tBSCertificate.subject.encode(tBSCertificate.subject)),
            DerFunctions.fromBytes(tBSCertificate.subjectPublicKeyInfo.encode(tBSCertificate.subjectPublicKeyInfo)),
            DerFunctions.fromBytes(tBSCertificate.extensions.encode(tBSCertificate.extensions))
        ]).toBytes();
    }
}
