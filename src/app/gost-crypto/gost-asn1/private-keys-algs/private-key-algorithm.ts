import {BERElement, ObjectIdentifier} from 'asn1-ts';
import {BERtypes} from '../structure/BERTypes';




// tslint:disable-next-line:no-empty-interface
export interface PrivateKeyAlgorithm {}


export class PrivateKeyAlgorithmRSA implements PrivateKeyAlgorithm {
    name: string;
    hash: any;
    id: string;


    constructor(name: string, hash: any, id: string) {
        this.name = name;
        this.hash = hash;
        this.id = id;
    }

    public static decode(value: ArrayBuffer) {
        throw Error('PrivateKeyAlgorithmRSA decode Not implemented');
    }

    public static encode(value: PrivateKeyAlgorithmRSA): ArrayBuffer {
        let sequence: BERElement[] = [];
        let privateKeyAlgorithm: BERElement;

        if (value.name === 'RSASSA-PKCS1-v1_5' && value.id === 'rsaEncryption') {
            privateKeyAlgorithm = new BERElement(); // 1.2.840.113549.1.1.1
            privateKeyAlgorithm.objectIdentifier = new ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]);
            privateKeyAlgorithm.tagNumber = BERtypes['OBJECT IDENTIFIER'];
            sequence.push(privateKeyAlgorithm);

            let n: BERElement = new BERElement();
            n.tagNumber = BERtypes.NULL;
            sequence.push(n);
        }


        let toReturn: BERElement = new BERElement();
        toReturn.sequence = sequence;
        toReturn.tagNumber = BERtypes.SEQUENCE;
        return toReturn.toBytes();
    }

}

export class PrivateKeyAlgorithmGost implements PrivateKeyAlgorithm{
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

    public static decode(value: ArrayBuffer) {
        throw Error('PrivateKeyAlgorithmGost decode Not implemented');
    }

    public static encode(value: PrivateKeyAlgorithmRSA): ArrayBuffer {
        let sequence: BERElement[] = [];
        let privateKeyAlgorithm: BERElement;

        if (value.name === 'RSASSA-PKCS1-v1_5' && value.id === 'rsaEncryption') {
            privateKeyAlgorithm = new BERElement(); // 1.2.840.113549.1.1.1
            privateKeyAlgorithm.objectIdentifier = new ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]);
            privateKeyAlgorithm.tagNumber = BERtypes['OBJECT IDENTIFIER'];
            sequence.push(privateKeyAlgorithm);

            let n: BERElement = new BERElement();
            n.tagNumber = BERtypes.NULL;
            sequence.push(n);
        }


        let toReturn: BERElement = new BERElement();
        toReturn.sequence = sequence;
        toReturn.tagNumber = BERtypes.SEQUENCE;
        return toReturn.toBytes();
    }

}
