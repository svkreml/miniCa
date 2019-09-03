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
        return toReturn.toBytes();
    }

}

export class Validity {
}

export class CertExtensions {
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

    public encode(value: TBSCertificate): ArrayBuffer {
        throw Error('Unsuported \n' + JSON.stringify(value));
    }
}
