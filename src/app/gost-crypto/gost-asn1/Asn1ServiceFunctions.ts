import {BER, Chars, PEM} from '../gost-coding/gost-coding';
import {BERElement, ObjectIdentifier} from 'asn1-ts';
import {toNumbers} from '@angular/compiler-cli/src/diagnostics/typescript_version';
import {BERtypes} from './structure/BERTypes';

export class Asn1ServiceFunctions {
    // Swap bytes in buffer
    static swapBytes(src) {
        if (src instanceof ArrayBuffer) {
            src = new Uint8Array(src);
        }
        const dst = new Uint8Array(src.length);
        for (let i = 0, n = src.length; i < n; i++) {
            dst[n - i - 1] = src[i];
        }
        return dst.buffer;
    }

    static isBinary(value) {
        return value instanceof ArrayBuffer || value.buffer instanceof ArrayBuffer;
    }

    // Left pad zero
    static lpad(n, width) {
        return n.length >= width ? n : new Array(width - n.length + 1).join('0') + n;
    }

    // Nearest power 2
    static npw2(n) {
        return n <= 2 ? n : n <= 4 ? 4 : n <= 8 ? 8 : n <= 16 ? 16 :
            n <= 32 ? 32 : n <= 64 ? 64 : n <= 128 ? 128 : n <= 256 ? 256 :
                n < 512 ? 512 : n < 1024 ? 1024 : undefined;
    }

    // Assert invalid message
    static assert(value) {
        if (value) {
            throw Error('Invalid format');
        }
    }

    static encode(format, object, tagNumber, tagClass, tagConstructed, uniformTitle) {
        Asn1ServiceFunctions.assert(object === undefined);
        let source: { tagNumber: any; tagClass: any; tagConstructed: any; object: any } | string = {
            tagNumber,
            tagClass: tagClass || 0x00,
            tagConstructed: tagConstructed || false,
            object
        };
        // Output format
        format = format || 'DER';
        if (format === 'DER' || format === 'CER') {
            source = BER.encode(source, format, undefined);
        }
        if (format === 'PEM') {
            source = PEM.encode(source, uniformTitle);
        }
        return source;
    }

    // Decode object primitive
    static decode(source, tagNumber, tagClass, tagConstructed, uniformTitle) {
        Asn1ServiceFunctions.assert(source === undefined);

        // Decode PEM
        if (typeof source === 'string') {
            source = PEM.decode(source, uniformTitle, false, undefined);
        }
        // Decode binary data
        if (source instanceof ArrayBuffer) {
            try {
                source = PEM.decode(Chars.encode(source, undefined), uniformTitle, true, undefined);
            } catch (e) {
                source = BER.decode(source);
            }
        }

        tagClass = tagClass || 0;
        tagConstructed = tagConstructed || false;
        // Restore context implicit formats
        if (source.tagNumber === undefined) {
            source = this.encode(true, source.object, tagNumber, tagClass,
                source.object instanceof Array, undefined);
            source = BER.decode(source);
        }

        // Check format
        Asn1ServiceFunctions.assert(source.tagClass !== tagClass ||
            source.tagNumber !== tagNumber ||
            source.tagConstructed !== tagConstructed);
        // Clone value define from redefine original
        if (tagClass === 0 && tagNumber === 0x05) {
            return null;
        } else {
            return source.object;
        }
    }
    public static convertOid(oid: string) {
        let element = new BERElement();
        element.objectIdentifier = new ObjectIdentifier(toNumbers(oid)); // toNumbers('2.0.1'); // returns [2, 0, 1]
        element.tagNumber = BERtypes['OBJECT IDENTIFIER'];
        return element;
    }

    public static createSequence(elements: BERElement[]) {
        let sequenceElement: BERElement = new BERElement();
        sequenceElement.tagNumber = BERtypes.SEQUENCE;
        sequenceElement.sequence = elements;
        return sequenceElement;
    }
}
