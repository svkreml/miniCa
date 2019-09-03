import {DERElement} from 'asn1-ts';

export enum BERtypes {
    'EOC' = 0x00, //
    'BOOLEAN' = 0x01, //
    'INTEGER' = 0x02, //
    'BIT STRING' = 0x03, //
    'OCTET STRING' = 0x04, //
    'NULL' = 0x05, //
    'OBJECT IDENTIFIER' = 0x06, //
    'ObjectDescriptor' = 0x07, //
    'EXTERNAL' = 0x08, //
    'REAL' = 0x09, //
    'ENUMERATED' = 0x0A, //
    'EMBEDDED PDV' = 0x0B, //
    'UTF8String' = 0x0C, //
    'SEQUENCE' = 0x10, //
    'SET' = 0x11, //
    'NumericString' = 0x12, //
    'PrintableString' = 0x13, //
    'TeletexString' = 0x14, //
    'VideotexString' = 0x15, //
    'IA5String' = 0x16, //
    'UTCTime' = 0x17, //
    'GeneralizedTime' = 0x18, //
    'GraphicString' = 0x19, //
    'VisibleString' = 0x1A, //
    'GeneralString' = 0x1B, //
    'UniversalString' = 0x1C, //
    'BMPString' = 0x1E
}

export function getValueFromDer(input: DERElement): any {
    switch (input.tagNumber) {
        case 0x00:
            return null;
        case 0x01:
            return input.boolean;
        case 0x02:
            return input.integer;
        case 0x03:
            return input.bitString;
        case 0x04:
            return input.octetString;
        case 0x05:
            return null;
        case 0x06:
            return input.objectIdentifier;
        case 0x07:
            return input.objectDescriptor;
        case 0x08:
            throw Error('tagNumber EXTERNAL unsuported');
        case 0x09:
            return input.real;
        case 0x0A:
            return input.enumerated;
        case 0x0B:
            throw Error('tagNumber EMBEDDED PDV unsuported');
        case 0x0C:
            return input.utf8String;
        case 0x10:
            return input.sequence;
        case 0x11:
            return input.set;
        case 0x12:
            return input.numericString;
        case 0x13:
            return input.printableString;
        case 0x14:
            return input.teletexString;
        case 0x15:
            return input.videotexString;
        case 0x16:
            return input.ia5String;
        case 0x17:
            return input.utcTime;
        case 0x18:
            return input.generalizedTime;
        case 0x19:
            return input.graphicString;
        case 0x1A:
            return input.visibleString;
        case 0x1B:
            return input.generalString;
        case 0x1C:
            return input.universalString;
        case 0x1E:
            return input.bmpString;
        default:
            throw Error('tagNumber error');
    }
}
