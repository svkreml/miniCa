import {DERElement} from 'asn1-ts';
import {BERtypes} from '../structure/BERTypes';
import {DerFunctions} from '../DerFunctions';
import {GostSecurity} from '../../gost-security/gost-security';


// tslint:disable-next-line:no-empty-interface
export interface PrivateKeyAlgorithm {
    decode(value: ArrayBuffer): PrivateKeyAlgorithm;
    encode(value: PrivateKeyAlgorithm): ArrayBuffer;
}


export class PrivateKeyAlgorithmRSA implements PrivateKeyAlgorithm {
    name: string;
    hash: any;
    id: string;


    constructor(name: string, hash: any, id: string) {
        this.name = name;
        this.hash = hash;
        this.id = id;
    }

    public decode(value: ArrayBuffer): PrivateKeyAlgorithm {
        throw Error('PrivateKeyAlgorithmRSA decode Not implemented');
    }

    public encode(value: PrivateKeyAlgorithmRSA): ArrayBuffer {
        let sequence: DERElement[] = [];
        let privateKeyAlgorithm: DERElement;

        if (value.name === 'RSASSA-PKCS1-v1_5' && value.id === 'rsaEncryption') {
            sequence.push(DerFunctions.convertOid(GostSecurity.instance.identifiers[value.id]));

            let n: DERElement = new DERElement();
            n.tagNumber = BERtypes.NULL;
            sequence.push(n);
        } else {
            throw Error('Unsuported \n' + JSON.stringify(value));
        }


        let toReturn: DERElement = new DERElement();
        toReturn.sequence = sequence;
        toReturn.tagNumber = BERtypes.SEQUENCE;
        return toReturn.toBytes();
    }

}


export class PrivateKeyAlgorithmGost implements PrivateKeyAlgorithm {
    name: string;
    id: string;
    namedCurve: string;
    sBox: string;


    constructor(name: string, id: string, namedCurve: string, sBox: string) {
        this.name = name;
        this.id = id;
        this.namedCurve = namedCurve;
        this.sBox = sBox;
    }

    public decode(value: ArrayBuffer): PrivateKeyAlgorithm {
        throw Error('PrivateKeyAlgorithmGost decode Not implemented');
    }

    public encode(value: PrivateKeyAlgorithm): ArrayBuffer {
        if (!(value instanceof PrivateKeyAlgorithmGost)) {
            throw Error('Unsuported \n' + JSON.stringify(value));
        }
        let toReturn: DERElement = new DERElement();
        if (value.name === 'GOST R 34.10-2001-DH' && value.id === 'id-GostR3410-2001DH') {
            let innerSeq: DERElement = DerFunctions.createSequence([
                DerFunctions.convertOid('1.2.643.2.2.36.0'),
                DerFunctions.convertOid('1.2.643.2.2.30.1')
            ]);
            toReturn = DerFunctions.createSequence([DerFunctions.convertOid('1.2.643.2.2.98'),
                innerSeq]);
        }
        else if (value.name === 'GOST R 34.10-256-DH/GOST R 34.11-256' && value.id === 'id-tc26-agreement-gost-3410-12-256') {
            let innerSeq: DERElement = DerFunctions.createSequence([
                DerFunctions.convertOid(GostSecurity.instance.identifiers['id-GostR3410-2001-CryptoPro-XchA-ParamSet']),
                DerFunctions.convertOid(GostSecurity.instance.identifiers['id-tc26-gost3411-12-256']),
            ]);
            toReturn = DerFunctions.createSequence([DerFunctions.convertOid(GostSecurity.instance.identifiers['id-tc26-agreement-gost-3410-12-256']),
                innerSeq]);
        }
        else if (value.name === 'GOST R 34.10-512-DH/GOST R 34.11-256' && value.id === 'id-tc26-agreement-gost-3410-12-512') {
            let innerSeq: DERElement = DerFunctions.createSequence([
                DerFunctions.convertOid(GostSecurity.instance.identifiers['id-tc26-gost-3410-12-512-paramSetA']),
                DerFunctions.convertOid(GostSecurity.instance.identifiers['id-tc26-gost3411-12-512']),
            ]);
            toReturn = DerFunctions.createSequence([DerFunctions.convertOid(GostSecurity.instance.identifiers['id-tc26-agreement-gost-3410-12-512']),
                innerSeq]);
        } else {
            throw Error('Unsuported \n' + JSON.stringify(value));
        }
        return toReturn.toBytes();
    }

}
