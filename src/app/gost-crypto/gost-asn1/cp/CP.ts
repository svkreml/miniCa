import {BERElement, DERElement} from 'asn1-ts';
import {BERtypes} from '../structure/BERTypes';
import {DerFunctions} from '../DerFunctions';

export class GostKeyContainer {
    containerAlgoritmIdentifier;
    attributes;
    primaryCertificate;
    primaryFP;
    extensions;
    hmacKeyContainerContent;
}

export class GostKeyContainerName {
    containerName: string; // ia5string
    extElem1: any; // wtf
    constructor(containerName: string, extElem1: any) {
        this.containerName = containerName;
        this.extElem1 = extElem1;
    }

    public static decode(value: ArrayBuffer): GostKeyContainerName {
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
        let toReturn: BERElement[] = [];


        let containerName: BERElement = new BERElement();
        containerName.ia5String = value.containerName;
        containerName.tagNumber = BERtypes.IA5String;
        toReturn.push(containerName);

        if (value.extElem1) {
            let extElem1: BERElement = new BERElement();
            extElem1.fromBytes(value.extElem1);
            toReturn.push(extElem1);
        }

        let constracted = new BERElement();
        constracted.sequence = toReturn;
        constracted.tagNumber = BERtypes.SEQUENCE;
        return constracted.toBytes();
    }
}

export class GostPrivateKeys {
    primaryKey: ArrayBuffer; // OctetString in sequence


    constructor(primaryKey: ArrayBuffer) {
        this.primaryKey = primaryKey;
    }

    public decode(value: ArrayBuffer): GostPrivateKeys {
        try {
            let encodedData: Uint8Array = new Uint8Array(value);
            let derElement: DERElement = new DERElement();
            derElement.fromBytes(encodedData);
            return new GostPrivateKeys(derElement.sequence[0].octetString);
        } catch (e) {
            throw Error(e);
        }

    }

    public encode(value: GostPrivateKeys): ArrayBuffer {
        return DerFunctions.createSequence([DerFunctions.createOctetString(value.primaryKey)]).toBytes();
    }
}

export class GostPrivateMasks {
    mask: ArrayBuffer; // OctetString in sequence
    randomStatus: ArrayBuffer; // OctetString in sequence
    hmacRandom: ArrayBuffer; // OctetString in sequence

    constructor(mask: ArrayBuffer, randomStatus: ArrayBuffer, hmacRandom: ArrayBuffer) {
        this.mask = mask;
        this.randomStatus = randomStatus;
        this.hmacRandom = hmacRandom;
    }

    public decode(value: ArrayBuffer): GostPrivateMasks {
        try {
            let encodedData: Uint8Array = new Uint8Array(value);
            let derElement: DERElement = new DERElement();
            derElement.fromBytes(encodedData);
            return new GostPrivateMasks(derElement.sequence[0].octetString, derElement.sequence[1].octetString, derElement.sequence[2].octetString);
        } catch (e) {
            throw Error(e);
        }

    }

    public encode(value: GostPrivateMasks): ArrayBuffer {
        return DerFunctions.createSequence([DerFunctions.createOctetString(value.mask),
            DerFunctions.createOctetString(value.randomStatus),
            DerFunctions.createOctetString(value.hmacRandom)]).toBytes();
    }
}
