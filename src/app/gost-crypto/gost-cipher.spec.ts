import {GostCipher} from './gost-cipher';
import {GostRandom} from './gost-random';
import {AlgorithmIndentifier} from '../dto/algorithm-indentifier';
import {Hex} from './gost-utils';

function perform(algorithm: AlgorithmIndentifier, key: string,  input: string,  output: string) {
    if (algorithm.iv) {
        (algorithm.iv = Hex.decode(algorithm.iv));
    }
    let cipher = new GostCipher(new GostRandom(), algorithm);
    let result = 'Test ' + ' ' + (cipher.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';

    try {
        let out = Hex.encode(cipher.encrypt(Hex.decode(key), Hex.decode(input), undefined));
        let test = (output && out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase() !== output.toLowerCase());


        if (!test) {
            out = Hex.encode(cipher.decrypt(Hex.decode(key), Hex.decode(out), undefined));
            if (!test) {
                result += 'PASSED';
            } else {
                result += 'FAILED - Decrypt expected ' + input + ' got ' + out;
            }
        } else {
            result += 'FAILED - Encrypt expected ' + output + ' got ' + out;
        }
    } catch (e) {
        result += 'FAILED - Throw error: ' + e.message;
    }
    console.log(result);
    return result;
}

function performMac(algorithm: AlgorithmIndentifier, key: string, input: string, output: string) {
    if (algorithm.iv) {
        (algorithm.iv = Hex.decode(algorithm.iv));
    }

    let cipher = new GostCipher(new GostRandom(), algorithm);
    let result = 'Test ' +  ' ' + (cipher.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    try {
        let out = Hex.encode(cipher.sign(Hex.decode(key), Hex.decode(input), undefined));
        let test = (output && out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase() !== output.toLowerCase());
        if (!test) {
            let res = cipher.verify(Hex.decode(key), Hex.decode(out), Hex.decode(input), undefined);
            test =  (!res);
            if (!test) {
                result += 'PASSED';
            } else {
                result += 'FAILED - Verify return (false)';
            }
        } else {
            result += 'FAILED - Sign expected ' + output + ' got ' + out;
        }
    } catch (e) {
        result += 'FAILED - Throw error: ' + e.message;
    }
    console.log(result);
    return result;
}

describe('GostCipher', () => {
    let testSBox = new Uint8Array([
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0xF, 0xE, 0xD, 0xC, 0xB, 0xA, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0xF, 0xE, 0xD, 0xC, 0xB, 0xA, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0xF, 0xE, 0xD, 0xC, 0xB, 0xA, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0xF, 0xE, 0xD, 0xC, 0xB, 0xA, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0
    ]);
    let input1 = '0000000000000000';
    let output1 = '1b0bbc32cebcab42';
    let input2 = 'bc350e71aac5f5c2';
    let output2 = 'd35ab653493b49f5';
    let input3 = 'bc350e71aa11345709acde';
    let output3 = '8824c124c4fd14301fb1e8';
    let input4 = '000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f';
    let output4 = '29b7083e0a6d955ca0ec5b04fdb4ea41949f1dd2efdf17baffc1780b031f3934';


    let gkeyBytes5 = '6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49';
    let gkeyBytes6 = '6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49';

    let input5 = '7768617420646f2079612077616e7420666f72206e6f7468696e673f';
    let input6 = '7768617420646f2079612077616e7420666f72206e6f7468696e673f';

    let output5 = '93468a46';
    let output6 = '93468a46';

    it('1 GOST 28147-89/GOST R 34.12-2015 TEST', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();
        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'D-TEST';
        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, input1, output1);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('2 GOST 28147-89/GOST R 34.12-2015 TEST', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.block = 'CBC';
        algorithm.sBox = 'D-TEST';
        algorithm.iv = '1234567890abcdef';

        let key = '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF';

        let result = perform(algorithm, key, input2, output2);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('3 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.block = 'CTR';
        algorithm.sBox = 'D-TEST';
        algorithm.iv = '1234567890abcdef';

        let key = '0011223344556677889900112233445566778899001122334455667788990011';

        let result = perform(algorithm, key, input3, output3);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('4 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'D-TEST';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, input1, output1);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('5 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'D-TEST';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, input1, output1);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('6 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'D-TEST';
        algorithm.block = 'CFB';
        algorithm.iv = '1234567890abcdef';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, '0000000000000000', 'b587f7a0814c911d');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('7 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'E-TEST';
        algorithm.block = 'CFB';
        algorithm.iv = '1234567890abcdef';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, '0000000000000000', 'e8287f53f991d52b');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('8 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'E-A';
        algorithm.shiftBits = 64;
        algorithm.block = 'CFB';
        algorithm.iv = '1234567890abcdef';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, '0000000000000000', 'c41009dba22ebe35');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('9 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        /*
        tests += perform(++i, {name: 'GOST 28147', block: 'CFB', iv: '1234567890abcdef', sBox: 'E-B', shiftBits: 8},
        '546d203368656c326973652073736e62206167796967747473656865202c3d73', '0000000000000000', '80d8723fcd3aba28');
        * */

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'E-B';
        algorithm.shiftBits = 8;
        algorithm.block = 'CFB';
        algorithm.iv = '1234567890abcdef';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, '0000000000000000', '80d8723fcd3aba28');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('10 GGOST 28147-89/GOST R 34.12-2015 TEST', () => {

        /*
        tests += perform(++i, {name: 'GOST 28147', block: 'CFB', shiftBits: 8, iv: '1234567890abcdef', sBox: 'E-C'},
        '546d203368656c326973652073736e62206167796967747473656865202c3d73', '0000000000000000', '739f6f95068499b5');
        * */

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'E-C';
        algorithm.shiftBits = 8;
        algorithm.block = 'CFB';
        algorithm.iv = '1234567890abcdef';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, '0000000000000000', '739f6f95068499b5');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('11 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        /*
        tests += perform(++i, {name: 'GOST 28147', block: 'CFB', shiftBits: 8, iv: '1234567890abcdef', sBox: 'E-D'},
        '546d203368656c326973652073736e62206167796967747473656865202c3d73', '0000000000000000', '4663f720f4340f57');
        * */

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'E-D';
        algorithm.shiftBits = 8;
        algorithm.block = 'CFB';
        algorithm.iv = '1234567890abcdef';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, '0000000000000000', '4663f720f4340f57');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('12 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        /*
        tests += perform(++i, {name: 'GOST 28147', block: 'CFB', shiftBits: 8, iv: '1234567890abcdef', sBox: 'D-A'},
        '546d203368656c326973652073736e62206167796967747473656865202c3d73', '0000000000000000', '5bb0a31d218ed564');
        * */

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'D-A';
        algorithm.shiftBits = 8;
        algorithm.block = 'CFB';
        algorithm.iv = '1234567890abcdef';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, '0000000000000000', '5bb0a31d218ed564');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('13 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        /*
      tests += perform(++i, {name: 'GOST 28147', block: 'CFB', shiftBits: 8, iv: '1234567890abcdef', sBox: TestSBox},
        '546d203368656c326973652073736e62206167796967747473656865202c3d73', '0000000000000000', 'c3af96ef788667c5');
        * */

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = testSBox;
        algorithm.shiftBits = 8;
        algorithm.block = 'CFB';
        algorithm.iv = '1234567890abcdef';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, '0000000000000000', 'c3af96ef788667c5');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('14 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        /*
        tests += perform(++i, {name: 'GOST 28147', block: 'CTR', iv: '1234567890abcdef', sBox: 'E-A'},
        '4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d', 'bc350e71aa11345709acde', '1bcc2282707c676fb656dc');
        * */

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'E-A';
        algorithm.shiftBits = 8;
        algorithm.block = 'CTR';
        algorithm.iv = '1234567890abcdef';

        let key = '4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d';

        let result = perform(algorithm, key, 'bc350e71aa11345709acde', '1bcc2282707c676fb656dc');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('15 GOST 28147-89/GOST R 34.12-2015 TEST', () => {

        /*
        tests += perform(++i, {name: 'GOST 28147', block: 'CTR', iv: '1234567890abcdef', sBox: 'E-A'},
        '4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d', 'bc350e71aa11345709acde', '1bcc2282707c676fb656dc');
        * */

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'E-Z';
      //  algorithm.shiftBits = 8;
        algorithm.block = 'ECB';
      //  algorithm.iv = '1234567890abcdef';

        let key = '8182838485868788898a8b8c8d8e8f80d1d2d3d4d5d6d7d8d9dadbdcdddedfd0';

        let result = perform(algorithm, key, '0102030405060708f1f2f3f4f5f6f7f8', 'ce5a5ed7e0577a5fd0cc85ce31635b8b');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('1 MAC sing/verify', () => {



        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.mode = 'MAC';
        algorithm.sBox = 'E-A';
        //  algorithm.shiftBits = 8;
       // algorithm.block = 'ECB';
        //  algorithm.iv = '1234567890abcdef';

        let key = '8182838485868788898a8b8c8d8e8f80d1d2d3d4d5d6d7d8d9dadbdcdddedfd0';

        let result = performMac(algorithm, gkeyBytes5, input5, output5);
        expect(result.includes('PASSED')).toBeTruthy();
    });
});
