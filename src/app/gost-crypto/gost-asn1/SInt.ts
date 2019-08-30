import {Hex} from '../gost-coding/gost-coding';
import {Asn1ServiceFunctions} from './Asn1ServiceFunctions';

export class SInt {


    static encode(value, endian): any {
        return '0x' + Hex.encode(value, endian);
    }

    static decode(value, endian, len): any {
        if (typeof value === 'number') {
            value = value.toString(16);
        }
        const s = value.replace('0x', '');
        len = len || Asn1ServiceFunctions.npw2(s.length);
        return Hex.decode(Asn1ServiceFunctions.lpad(s, len), endian);
    }
}
