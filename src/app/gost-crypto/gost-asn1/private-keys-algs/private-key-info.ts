import {PrivateKeyAlgorithmGost, PrivateKeyAlgorithmRSA} from './private-key-algorithm';
import {BERElement} from 'asn1-ts';
import {BERtypes} from '../structure/BERTypes';

export class PrivateKeyInfo {
    version: number;
    privateKeyAlgorithm: PrivateKeyAlgorithmRSA;
    privateKey: Uint8Array;


    constructor(version: number, privateKeyAlgorithm: PrivateKeyAlgorithmRSA, privateKey: Uint8Array) {
        this.version = version;
        this.privateKeyAlgorithm = privateKeyAlgorithm;
        this.privateKey = privateKey;
    }

    public decode(value: ArrayBuffer): PrivateKeyInfo {
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
                case '1.2.840.113549.1.1.1': // TODO как минимум надо добаить ГОСТ 2001 и два 2012
                    privateKeyAlgorithm = new PrivateKeyAlgorithmRSA('RSASSA-PKCS1-v1_5',
                        {
                            name: 'SHA-256'
                        },
                        'rsaEncryption');
                    break;
                case '1.2.643.2.2.98': // ГОСТ 2001
                    privateKeyAlgorithm = new PrivateKeyAlgorithmGost('GOST R 34.10-2001-DH',
                        'id-GostR3410-2001DH',
                        'X-256-A',
                        'D-A');
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


    public encode(value: PrivateKeyInfo): ArrayBuffer {
        let sequence: BERElement[] = [];

        let version: BERElement = new BERElement();
        version.integer = value.version;
        version.tagNumber = BERtypes.INTEGER;
        sequence.push(version);

        let privateKeyAlgorithm: BERElement = new BERElement();
        privateKeyAlgorithm.fromBytes(new Uint8Array(value.privateKeyAlgorithm.encode(value.privateKeyAlgorithm)));
        privateKeyAlgorithm.tagNumber = BERtypes.SEQUENCE; // BERtypes['OCTET STRING'];
        sequence.push(privateKeyAlgorithm);

        let privateKey: BERElement = new BERElement();
        privateKey.fromBytes(value.privateKey);
      //  privateKey.tagNumber = BERtypes.SEQUENCE;

        let privateKeyWrapper: BERElement = new BERElement();
        privateKeyWrapper.octetString = privateKey.toBytes();
        privateKeyWrapper.tagNumber = BERtypes['OCTET STRING'];

        sequence.push(privateKeyWrapper);



        let toReturn: BERElement = new BERElement();
        toReturn.sequence = sequence;
        toReturn.tagNumber = BERtypes.SEQUENCE;
        return toReturn.toBytes();
    }
}

