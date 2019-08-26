import {GostCipher} from './gost-cipher';
import {GostRandom} from './gost-random';
import {AlgorithmIndentifier} from '../dto/algorithm-indentifier';
import {Hex} from './gost-coding';


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

    it('1 GOST 28147-89', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();
        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'D-TEST';
        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, input1, output1);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('2 GOST 28147-89', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.block = 'CBC';
        algorithm.sBox = 'D-TEST';
        algorithm.iv = '1234567890abcdef';

        let key = '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF';

        let result = perform(algorithm, key, input2, output2);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('3 GOST 28147-89', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.block = 'CTR';
        algorithm.sBox = 'D-TEST';
        algorithm.iv = '1234567890abcdef';

        let key = '0011223344556677889900112233445566778899001122334455667788990011';

        let result = perform(algorithm, key, input3, output3);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('4 GOST 28147-89', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();
        algorithm.block = 'CFB';
        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'D-TEST';
        algorithm.iv = 'aafd12f659cae634';
        let key = 'aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5';

        let result = perform(algorithm, key, input4, output4);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('5 GOST 28147-89', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'D-TEST';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, input1, output1);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('6 GOST 28147-89', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'D-TEST';
        algorithm.block = 'CFB';
        algorithm.iv = '1234567890abcdef';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, '0000000000000000', 'b587f7a0814c911d');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('7 GOST 28147-89', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.sBox = 'E-TEST';
        algorithm.block = 'CFB';
        algorithm.iv = '1234567890abcdef';

        let key = '546d203368656c326973652073736e62206167796967747473656865202c3d73';

        let result = perform(algorithm, key, '0000000000000000', 'e8287f53f991d52b');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('8 GOST 28147-89', () => {

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

    it('9 GOST 28147-89', () => {

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


    it('10 GGOST 28147-89', () => {

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


    it('11 GOST 28147-89', () => {

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


    it('12 GOST 28147-89', () => {

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

    it('13 GOST 28147-89', () => {

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

    it('14 GOST 28147-89', () => {

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

    it('15 GOST 28147-89', () => {

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

        let result = performMac(algorithm, gkeyBytes5, input5, output5);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('2 MAC sing/verify', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.mode = 'MAC';
        algorithm.sBox = 'E-A';
        //  algorithm.shiftBits = 8;
        // algorithm.block = 'ECB';
        //  algorithm.iv = '1234567890abcdef';

        let result = performMac(algorithm, gkeyBytes6, input6, output6);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('1 Padding', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.name = 'BIT';
        //  algorithm.mode = 'MAC';
        algorithm.sBox = 'D-TEST';
        //  algorithm.shiftBits = 8;
        // algorithm.block = 'ECB';
        //  algorithm.iv = '1234567890abcdef';

        let result = perform(algorithm, '546d203368656c326973652073736e62206167796967747473656865202c3d73', 'fedcba98765432', undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('2 Padding', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.name = 'BIT';
        //  algorithm.mode = 'MAC';
        algorithm.sBox = 'D-TEST';
        //  algorithm.shiftBits = 8;
        // algorithm.block = 'ECB';
        //  algorithm.iv = '1234567890abcdef';

        let result = perform(algorithm, '546d203368656c326973652073736e62206167796967747473656865202c3d73', 'fedcba9876543210', undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('3 Padding', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.name = 'PKCS5P';
        //  algorithm.mode = 'MAC';
        algorithm.sBox = 'D-TEST';
        //  algorithm.shiftBits = 8;
        // algorithm.block = 'ECB';
        //  algorithm.iv = '1234567890abcdef';

        let result = perform(algorithm, '546d203368656c326973652073736e62206167796967747473656865202c3d73', 'fedcba98765432', undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('4 Padding', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.name = 'PKCS5P';
        //  algorithm.mode = 'MAC';
        algorithm.sBox = 'D-TEST';
        //  algorithm.shiftBits = 8;
        // algorithm.block = 'ECB';
        //  algorithm.iv = '1234567890abcdef';

        let result = perform(algorithm, '546d203368656c326973652073736e62206167796967747473656865202c3d73', 'fedcba9876543210', undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('5 Padding', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        algorithm.name = 'ZERO';
        //  algorithm.mode = 'MAC';
        algorithm.sBox = 'D-TEST';
        //  algorithm.shiftBits = 8;
        // algorithm.block = 'ECB';
        //  algorithm.iv = '1234567890abcdef';

        let result = perform(algorithm, '546d203368656c326973652073736e62206167796967747473656865202c3d73', 'fedcba9876543210', undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    let input = new Array(10001).join('61');

    it('1 Key meshing', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        // algorithm.name = 'ZERO';
        //  algorithm.mode = 'MAC';
        algorithm.sBox = 'D-TEST';
        //  algorithm.shiftBits = 8;
        algorithm.block = 'CFB';
        algorithm.keyMeshing = 'CP';
        algorithm.iv = '1234567890abcdef';

        let result = perform(algorithm, '4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d', input, undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('2 Key meshing', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        // algorithm.name = 'ZERO';
        //  algorithm.mode = 'MAC';
        algorithm.sBox = 'D-TEST';
        //  algorithm.shiftBits = 8;
        algorithm.block = 'CBC';
        algorithm.keyMeshing = 'CP';
        algorithm.iv = '1234567890abcdef';

        let result = perform(algorithm, '4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d', input, undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('3 Key meshing', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        // algorithm.name = 'ZERO';
        //  algorithm.mode = 'MAC';
        algorithm.sBox = 'D-TEST';
        //  algorithm.shiftBits = 8;
        algorithm.block = 'CTR';
        algorithm.keyMeshing = 'CP';
        algorithm.iv = '1234567890abcdef';

        let result = perform(algorithm, '4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d', input, undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('4 Key meshing', () => {

        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        // algorithm.name = 'ZERO';
        algorithm.mode = 'MAC';
        algorithm.sBox = 'D-TEST';
        //  algorithm.shiftBits = 8;
        // algorithm.block = 'CTR';
        algorithm.keyMeshing = 'CP';
        algorithm.iv = '1234567890abcdef';

        let result = performMac(algorithm, '4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d', input, undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('1 Key wrapping', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        // algorithm.name = 'ZERO';
        algorithm.mode = 'KW';
        algorithm.sBox = 'D-TEST';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CTR';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcdef';
        algorithm.ukm = '1234567890abcdef';

        let result = performWrap(
            algorithm,
            'aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5',
            '6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49',
            'af502015229a831dc82b4d32dc00173f5d43d921e5e09cc09ce947c777414397022a90c7');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('2 Key wrapping', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        // algorithm.name = 'ZERO';
        algorithm.mode = 'KW';
        algorithm.sBox = 'E-A';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CTR';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcdef';
        algorithm.ukm = '1234567890abcdef';

        let result = performWrap(
            algorithm,
            'aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5',
            '6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49',
            undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('3 Key wrapping', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        // algorithm.name = 'ZERO';
        algorithm.mode = 'KW';
        algorithm.sBox = 'D-TEST';
        algorithm.keyWrapping = 'CP';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CTR';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcdef';
        algorithm.ukm = '1234567890abcdef';

        let result = performWrap(
            algorithm,
            'aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5',
            '6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49',
            '16256f060dd3b3d8734a9fcc9ab4c3d04e777dc5c46a2f4c3e411e3597a5bfc32b41e492');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('4 Key wrapping', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        // algorithm.name = 'ZERO';
        algorithm.mode = 'KW';
        algorithm.sBox = 'E-A';
        algorithm.keyWrapping = 'CP';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CTR';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcdef';
        algorithm.ukm = '1234567890abcdef';

        let result = performWrap(
            algorithm,
            'aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5',
            '6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49',
            undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('5 Key wrapping', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST 28147';
        // algorithm.name = 'ZERO';
        algorithm.mode = 'KW';
        algorithm.sBox = 'E-SC';
        algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CTR';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcdef';
        algorithm.ukm = '1234567890abcdef';

        let result = performWrap(
            algorithm,
            '2208cd6bc96a' +
            '009f05175f635bee6cc09c78260b9b7eee1e070d346462e6881bbf572f436df5' +
            '716b1212a9fba3d022db4aed0a18530ae6c62d9bdd206479805ce652c17bc9cc' +
            '07dcdce25cba19276285f6c54dfa940ab55473bde2d8338eaaedc59cdd808619' +
            'f75296db91e016b588c0650686ff6929258a76d5ca7ba91b7fa87f41b2deb535' +
            'a66b489a5485ac68971e00658836ce358dcda04b358621ebf08ce062b671d84a' +
            '30706495ee2ed7d0f0a6a3e171a9daba04b582c3b7113905053a5b9254c7e08b' +
            'ea27cb66e19699db55444f1e1f1b5a3b7db7cbcc04728e225e67ab8099dc82b1' +
            '5d6f4f794c0f584718252fb2d9ffffe6d2adc4c86616466fe032ed28790e6af6',
            '5a7145b0ee4c080e0fcf689e5222c25876ac9d2b25a68fb3357eea8f849d6272',
            '7c34bf4e03d0bc120768164f355cf6180b32851e2ad6fc22b386bbea17fa1d5f1789eb95');
        expect(result.includes('PASSED')).toBeTruthy();
    });



    let key64 = 'ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
    let inp64 = '92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41';
    it('1 GOST R 34.12-2015/64bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'KW';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CTR';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcdef';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key64,
            'fedcba9876543210',
            '4ee901e5c2d8ca3d');
        expect(result.includes('PASSED')).toBeTruthy();
    });



    it('2 GOST R 34.12-2015/64bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'KW';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        algorithm.block = 'ECB';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcdef';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key64,
            inp64,
            '2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb');
        expect(result.includes('PASSED')).toBeTruthy();
    });




    it('3 GOST R 34.12-2015/64bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'KW';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        algorithm.block = 'CTR';
        // algorithm.keyMeshing = 'CP';
        algorithm.iv = '12345678';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key64,
            inp64,
            '4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d');
        expect(result.includes('PASSED')).toBeTruthy();
    });



    it('4 GOST R 34.12-2015/64bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'KW';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        algorithm.iv = '1234567890abcdef234567890abcdef134567890abcdef12';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key64,
            inp64,
            '96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('5 GOST R 34.12-2015/64bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'KW';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        algorithm.block = 'CFB';
        // algorithm.keyMeshing = 'CP';
        algorithm.iv = '1234567890abcdef234567890abcdef1';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key64,
            inp64,
            'db37e0e266903c830d46644c1f9a089c24bdd2035315d38bbcc0321421075505');
        expect(result.includes('PASSED')).toBeTruthy();
    });



    it('6 GOST R 34.12-2015/64bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'KW';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        algorithm.block = 'OFB';
        // algorithm.keyMeshing = 'CP';
        algorithm.iv = '1234567890abcdef234567890abcdef1';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key64,
            inp64,
            'db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb05');
        expect(result.includes('PASSED')).toBeTruthy();
    });




    it('7 GOST R 34.12-2015/64bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        // algorithm.name = 'ZERO';
        algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'OFB';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcdef234567890abcdef1';
        // algorithm.ukm = '1234567890abcdef';

        let result = performMac(
            algorithm,
            key64,
            inp64,
            '154e7210');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    let key128 = '8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef';
    let inp128 = '1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a' +
                 '112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011';

    it('1 GOST R 34.12-2015/128bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        algorithm.length = 128;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'OFB';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcdef234567890abcdef1';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key128,
            '1122334455667700ffeeddccbbaa9988',
            '7f679d90bebc24305a468d42b9d4edcd');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('2 GOST R 34.12-2015/128bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        algorithm.length = 128;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'OFB';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcdef234567890abcdef1';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key128,
            inp128,
            '7f679d90bebc24305a468d42b9d4edcdb429912c6e0032f9285452d76718d08b' +
                    'f0ca33549d247ceef3f5a5313bd4b157d0b09ccde830b9eb3a02c4c5aa8ada98');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('3 GOST R 34.12-2015/128bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        algorithm.length = 128;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        algorithm.block = 'CTR';
        // algorithm.keyMeshing = 'CP';
        algorithm.iv = '1234567890abcef0';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key128,
            inp128,
            'f195d8bec10ed1dbd57b5fa240bda1b885eee733f6a13e5df33ce4b33c45dee4a5' +
            'eae88be6356ed3d5e877f13564a3a5cb91fab1f20cbab6d1c6d15820bdba73');
        expect(result.includes('PASSED')).toBeTruthy();
    });




    it('4 GOST R 34.12-2015/128bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        algorithm.length = 128;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        algorithm.block = 'OFB';
        // algorithm.keyMeshing = 'CP';
        algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key128,
            inp128,
            '81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf66a25' +
            '7ac3ca0b8b1c80fe7fc10288a13203ebbc066138660a0292243f6903150');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('5 GOST R 34.12-2015/128bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        algorithm.length = 128;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            key128,
            inp128,
            '689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5acfe7ba' +
            'bf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('6 GOST R 34.12-2015/128bits', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'GOST R 34.12';
        algorithm.version = 2015;
        algorithm.length = 128;
        // algorithm.name = 'ZERO';
        algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = performMac(
            algorithm,
            key128,
            inp128,
            '336f4d296059fbe3');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('1 RC2', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'RC2';
        algorithm.version = 1;
        algorithm.length = 63;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            '0000000000000000',
            '0000000000000000',
            'ebb773f993278eff');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('2 RC2', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'RC2';
        algorithm.version = 1;
        algorithm.length = 64;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            'ffffffffffffffff',
            'ffffffffffffffff',
            '278b27e42e2f0d49');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('3 RC2', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'RC2';
        algorithm.version = 1;
        algorithm.length = 64;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            '3000000000000000',
            '1000000000000001',
            '30649edf9be7d2c2');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('4 RC2', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'RC2';
        algorithm.version = 1;
        algorithm.length = 64;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            '88',
            '0000000000000000',
            '61a8a244adacccf0');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('5 RC2', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'RC2';
        algorithm.version = 1;
        algorithm.length = 64;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            '88bca90e90875a',
            '0000000000000000',
            '6ccf4308974c267f');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('6 RC2', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'RC2';
        algorithm.version = 1;
        algorithm.length = 64;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            '88bca90e90875a7f0f79c384627bafb2',
            '0000000000000000',
            '1a807d272bbe5db1');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('7 RC2', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'RC2';
        algorithm.version = 1;
        algorithm.length = 128;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            '88bca90e90875a7f0f79c384627bafb2',
            '0000000000000000',
            '2269552ab0f85ca6');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('8 RC2', () => {
        let algorithm: AlgorithmIndentifier = new AlgorithmIndentifier();

        algorithm.name = 'RC2';
        algorithm.version = 1;
        algorithm.length = 129;
        // algorithm.name = 'ZERO';
        // algorithm.mode = 'MAC';
        // algorithm.sBox = 'E-SC';
        // algorithm.keyWrapping = 'SC';
        // algorithm.shiftBits = 8;
        // algorithm.block = 'CBC';
        // algorithm.keyMeshing = 'CP';
        // algorithm.iv = '1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819';
        // algorithm.ukm = '1234567890abcdef';

        let result = perform(
            algorithm,
            '88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e',
            '0000000000000000',
            '5b78d3a43dfff1f1');
        expect(result.includes('PASSED')).toBeTruthy();
    });
});























function perform(algorithm: AlgorithmIndentifier, key: string, input: string, output: string) {
    if (algorithm.iv) {
        (algorithm.iv = Hex.decode(algorithm.iv));
    }
    let cipher = new GostCipher(new GostRandom(), algorithm);
    let result = 'Test ' + ' ' + (cipher.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';

    try {
        let out = Hex.encode(cipher.encrypt(Hex.decode(key), Hex.decode(input), undefined));
        let test = (output && out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase() !== output.toLowerCase());
        // console.log('-----------------');
        // console.log(out);

        if (!test) {
            out = Hex.encode(cipher.decrypt(Hex.decode(key), Hex.decode(out), undefined));
            // console.log('--------------');
            // console.log(out);
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
    let result = 'Test ' + ' ' + (cipher.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    try {
        let out = Hex.encode(cipher.sign(Hex.decode(key), Hex.decode(input), undefined));
        let test = (output && out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase() !== output.toLowerCase());
        if (!test) {
            let res = cipher.verify(Hex.decode(key), Hex.decode(out), Hex.decode(input), undefined);
            test = (!res);
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

function performWrap(algorithm: AlgorithmIndentifier, key: string, input: string, output: string) {

    if (algorithm.ukm) {
        (algorithm.ukm = Hex.decode(algorithm.ukm));
    }

    let cipher = new GostCipher(new GostRandom(), algorithm);
    let result = 'Test ' + ' ' + (cipher.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    try {
        let out = Hex.encode(cipher.wrapKey(Hex.decode(key), Hex.decode(input)));
        let test = (output && out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase() !== output.toLowerCase());
        if (!test) {
            out = Hex.encode(cipher.unwrapKey(Hex.decode(key), Hex.decode(out)));
            test = (out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase() !== input.toLowerCase());
            if (!test) {
                result += 'PASSED';
            } else {
                result += 'FAILED - Unwrap key expected ' + input + ' got ' + out;
            }
        } else {
            result += 'FAILED - Wrap key expected ' + output + ' got ' + out;
        }
    } catch (e) {
        result += 'FAILED - Throw error: ' + e.message;
    }
    console.log(result);
    return result;
}
