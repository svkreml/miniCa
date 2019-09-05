import {ASN1TagClass, DERElement, ObjectIdentifier} from 'asn1-ts';
import {toNumbers} from '@angular/compiler-cli/src/diagnostics/typescript_version';
import {BERtypes} from './structure/BERTypes';

export class DerFunctions {
    public static convertOid(oid: string): DERElement {
        let element = new DERElement();
        element.objectIdentifier = new ObjectIdentifier(toNumbers(oid)); // toNumbers('2.0.1'); // returns [2, 0, 1]
        element.tagNumber = BERtypes['OBJECT IDENTIFIER'];
        return element;
    }

    public static createOctetString(array: ArrayBuffer): DERElement {
        let element = new DERElement();
        element.octetString = new Uint8Array(array);
        element.tagNumber = BERtypes['OCTET STRING'];
        return element;
    }

    public static createInteger(value: number): DERElement {
        let element = new DERElement();
        element.integer = value;
        element.tagNumber = BERtypes.INTEGER;
        return element;
    }
    public static createUTF8String(value: string): DERElement {
        let element = new DERElement();
        element.utf8String = value;
        element.tagNumber = BERtypes.UTF8String;
        return element;
    }

    public static createByTag(input: any, tag: number): DERElement {
        let element: DERElement = new DERElement();
        element.tagNumber = tag;
        switch (tag) {
            case 0x00:
                break;
            case 0x01:
                element.boolean = Boolean(input);
                break;
            case 0x02:
                element.integer = Number(input);
                break;
            case 0x03:
                element.bitString = input;
                break;
            case 0x04:
                element.octetString = input;
                break;
            case 0x05:
                break;
            case 0x06:
                element.objectIdentifier = input;
                break;
            case 0x07:
                element.objectDescriptor = input;
                break;
            case 0x08:
                throw Error('tagNumber EXTERNAL unsuported');
            case 0x09:
                element.real = input;
                break;
            case 0x0A:
                element.enumerated = input;
                break;
            case 0x0B:
                throw Error('tagNumber EMBEDDED PDV unsuported');
            case 0x0C:
                element.utf8String = input;
                break;
            case 0x10:
                element.sequence = input;
                break;
            case 0x11:
                element.set = input;
                break;
            case 0x12:
                element.numericString = input;
                break;
            case 0x13:
                element.printableString = input;
                break;
            case 0x14:
                element.teletexString = input;
                break;
            case 0x15:
                element.videotexString = input;
                break;
            case 0x16:
                element.ia5String = input;
                break;
            case 0x17:
                element.utcTime = input;
                break;
            case 0x18:
                element.generalizedTime = input;
                break;
            case 0x19:
                element.graphicString = input;
                break;
            case 0xA0:
                element.construction = input;
                break;
                case 0x1A:
                element.visibleString = input;
                break;
            case 0x1B:
                element.generalString = input;
                break;
            case 0x1C:
                element.universalString = input;
                break;
            case 0x1E:
                element.bmpString = input;
                break;
            default:
                throw Error('tagNumber error');
        }
        return element;
    }


    public static createSequence(elements: DERElement[]) {
        let sequenceElement: DERElement = new DERElement();
        sequenceElement.tagNumber = BERtypes.SEQUENCE;
        sequenceElement.sequence = elements;
        return sequenceElement;
    }


    public static createSet(elements: DERElement[]) {
        let sequenceElement: DERElement = new DERElement();
        sequenceElement.tagNumber = BERtypes.SET;
        sequenceElement.sequence = elements;
        return sequenceElement;
    }

    static fromBytes(arrayBuffer: ArrayBuffer) {
        let sequenceElement: DERElement = new DERElement();
        sequenceElement.fromBytes(new Uint8Array(arrayBuffer));
        return sequenceElement;
    }

    static createVersion(version: number) {
        let element = new DERElement();
        element.integer = version;
        element.tagClass = ASN1TagClass.application;
        element.tagNumber = BERtypes.INTEGER;
        return element;
        // EXPLICIT
    }

    static printableString(value: string) {
        let element = new DERElement();
        element.utf8String = value;
        element.tagNumber = BERtypes.PrintableString;
        return element;
    }
}
