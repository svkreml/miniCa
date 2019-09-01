import {BERElement, ObjectIdentifier} from 'asn1-ts';
import {BERtypes} from '../structure/BERTypes';
import {Asn1ServiceFunctions} from '../Asn1ServiceFunctions';
import {sequence} from '@angular/animations';


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

    public encode(value: PrivateKeyAlgorithmRSA): ArrayBuffer {
        let toReturn: BERElement = new BERElement();
        if (value.name === 'GOST R 34.10-2001-DH' && value.id === 'id-GostR3410-2001DH') {

            // SEQUENCE {
//     1 OBJECT IDENTIFIER id-GostR3410-2001DH (1.2.643.2.2.98)

// }
            //     2 SEQUENCE {
//         1 OBJECT IDENTIFIER id-GostR3410-2001-CryptoPro-XchA-ParamSet (1.2.643.2.2.36.0)
//         2 OBJECT IDENTIFIER id-GostR3411-94-CryptoProParamSet (1.2.643.2.2.30.1)
//      }
            let innerSeq: BERElement = Asn1ServiceFunctions.createSequence([
                Asn1ServiceFunctions.convertOid('1.2.643.2.2.36.0'),
                Asn1ServiceFunctions.convertOid('1.2.643.2.2.30.1')
            ]);
            toReturn = Asn1ServiceFunctions.createSequence([Asn1ServiceFunctions.convertOid('1.2.643.2.2.98'),
                innerSeq]);
        }
        return toReturn.toBytes();
    }

}
