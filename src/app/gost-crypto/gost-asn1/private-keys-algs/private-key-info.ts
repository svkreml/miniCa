import {PrivateKeyAlgorithmGost, PrivateKeyAlgorithmRSA} from './private-key-algorithm';
import {DERElement} from 'asn1-ts';
import {BERtypes} from '../structure/BERTypes';
import {GostSecurity} from '../../gost-security/gost-security';

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
        let berElement: DERElement = new DERElement();
        berElement.fromBytes(encodedData);


        let version;
        let privateKeyAlgorithm;
        let privateKey;
        if (berElement.sequence[0]) {
            version = berElement.sequence[0].integer;
        }
        if (berElement.sequence[1]) {
            let objectIdentifier = berElement.sequence[1].sequence[0].objectIdentifier;
            let key;
            switch (objectIdentifier.dotDelimitedNotation) {

                case '1.2.840.113549.1.1.1': // TODO как минимум надо добаить ГОСТ 2001 и два 2012
                    privateKeyAlgorithm = new PrivateKeyAlgorithmRSA(
                        'RSASSA-PKCS1-v1_5',
                        {
                            name: 'SHA-256'
                        },
                        GostSecurity.instance.names[objectIdentifier.dotDelimitedNotation]);
                    break; // berElement.sequence[1].sequence[1].sequence[0].objectIdentifier.toString() 1.2.643.2.2.36.0 // berElement.sequence[1].sequence[1].sequence[1].objectIdentifier.toString() 1.2.643.2.2.30.1
                case '1.2.643.2.2.98': // ГОСТ 2001
                    key = GostSecurity.instance.providers['CP-01'].privateKey;
                    privateKeyAlgorithm = new PrivateKeyAlgorithmGost(key.name,
                        key.id,
                        key.namedCurve,
                        GostSecurity.instance.parameters[GostSecurity.instance.names[berElement.sequence[1].sequence[1].sequence[1].objectIdentifier.toString()]].sBox);
                    break;
                case '1.2.643.7.1.1.6.1': // ГОСТ 2012 256
                    key = GostSecurity.instance.providers['TC-256'].privateKey;
                    privateKeyAlgorithm = new PrivateKeyAlgorithmGost(key.name,
                        key.id,
                        key.namedCurve,
                        undefined);
                    break;
                case '1.2.643.7.1.1.6.2': // ГОСТ 2012 512
                    key = GostSecurity.instance.providers['TC-512'].privateKey;
                    privateKeyAlgorithm = new PrivateKeyAlgorithmGost(key.name,
                        key.id,
                        key.namedCurve,
                        undefined);
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
        let sequence: DERElement[] = [];

        let version: DERElement = new DERElement();
        version.integer = value.version;
        version.tagNumber = BERtypes.INTEGER;
        sequence.push(version);

        let privateKeyAlgorithm: DERElement = new DERElement();
        privateKeyAlgorithm.fromBytes(new Uint8Array(value.privateKeyAlgorithm.encode(value.privateKeyAlgorithm)));
        privateKeyAlgorithm.tagNumber = BERtypes.SEQUENCE; // BERtypes['OCTET STRING'];
        sequence.push(privateKeyAlgorithm);

        let privateKey: DERElement = new DERElement();
        privateKey.fromBytes(value.privateKey);
        //  privateKey.tagNumber = BERtypes.SEQUENCE;

        let privateKeyWrapper: DERElement = new DERElement();
        privateKeyWrapper.octetString = privateKey.toBytes();
        privateKeyWrapper.tagNumber = BERtypes['OCTET STRING'];

        sequence.push(privateKeyWrapper);


        let toReturn: DERElement = new DERElement();
        toReturn.sequence = sequence;
        toReturn.tagNumber = BERtypes.SEQUENCE;
        return toReturn.toBytes();
    }
}

