import {GostDigest} from './gost-digest';
import {GostRandom} from './gost-random';
import {GostCipher} from './gost-cipher';
import {AlgorithmIndentifier} from '../dto/algorithm-indentifier';
import {Chars, Hex} from './gost-coding';

describe('GostDigest', () => {

    let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();
    algorithm.name = 'GOST R 34.11';
    algorithm.version = 1994;
    let gostDigest = new GostDigest(algorithm);


    it('1 t', () => {


        let result = perform(gostDigest, Chars.decode('', undefined),
            '981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0');

        expect(result.includes('PASSED')).toBeTruthy();
    });
});


function perform(gostDigest: GostDigest, array: ArrayBuffer, a) {

    let start;
    let finish;
    let out;
    let result;
    let test;


    start = new Date().getTime();
    result = 'Test ' + ' ' + (gostDigest.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    try {

        out = Hex.encode(gostDigest.digest(array));
        finish = new Date().getTime();
        out = out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase();
        test = (out !== a);
        if (test) {
            result += 'FAILED: Expected ' + 'digest' + ' got ' + out;
        } else {
            result += 'PASSED ' + (finish - start) / 1000 + ' sec';
        }
    } catch (e) {
        result += 'FAILED - Throw error: ' + e.message;
    }

    console.log(result);
    return result;
}
