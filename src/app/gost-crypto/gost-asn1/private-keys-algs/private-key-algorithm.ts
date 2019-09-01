import {DERElement} from 'asn1-ts';
import {BERtypes} from '../structure/BERTypes';
import {Asn1ServiceFunctions} from '../Asn1ServiceFunctions';
import {GostSecurity} from '../../gost-security/gost-security';


// tslint:disable-next-line:no-empty-interface
export interface PrivateKeyAlgorithm {
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

    public decode(value: ArrayBuffer) {
        throw Error('PrivateKeyAlgorithmRSA decode Not implemented');
    }

    public encode(value: PrivateKeyAlgorithmRSA): ArrayBuffer {
        let sequence: DERElement[] = [];
        let privateKeyAlgorithm: DERElement;

        if (value.name === 'RSASSA-PKCS1-v1_5' && value.id === 'rsaEncryption') {
            sequence.push(Asn1ServiceFunctions.convertOid(GostSecurity.instance.identifiers[value.id]));

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

    public decode(value: ArrayBuffer) {
        throw Error('PrivateKeyAlgorithmGost decode Not implemented');
    }

    public encode(value: PrivateKeyAlgorithmGost): ArrayBuffer {
        let toReturn: DERElement = new DERElement();
        if (value.name === 'GOST R 34.10-2001-DH' && value.id === 'id-GostR3410-2001DH') {
            let innerSeq: DERElement = Asn1ServiceFunctions.createSequence([
                Asn1ServiceFunctions.convertOid('1.2.643.2.2.36.0'),
                Asn1ServiceFunctions.convertOid('1.2.643.2.2.30.1')
            ]);
            toReturn = Asn1ServiceFunctions.createSequence([Asn1ServiceFunctions.convertOid('1.2.643.2.2.98'),
                innerSeq]);
        } else if (value.name === 'GOST R 34.10-2001-DH' && value.id === 'id-GostR3410-2001DH') {
            let innerSeq: DERElement = Asn1ServiceFunctions.createSequence([
                Asn1ServiceFunctions.convertOid('1.2.643.2.2.36.0'),
                Asn1ServiceFunctions.convertOid('1.2.643.2.2.30.1')
            ]);
            toReturn = Asn1ServiceFunctions.createSequence([Asn1ServiceFunctions.convertOid('1.2.643.2.2.98'),
                innerSeq]);
        } else {
            throw Error('Unsuported \n' + JSON.stringify(value));
        }
        return toReturn.toBytes();
    }

}
