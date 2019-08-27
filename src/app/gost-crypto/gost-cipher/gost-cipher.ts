import {GostRandom} from '../gost-random/gost-random';
import {AlgorithmIndentifier} from '../../dto/algorithm-indentifier';
import {GostCoding} from '../gost-coding/gost-coding';


export class GostCipher {


    /*
    * selected from algorithm
    * */
    keySize: number;
    blockLength: number;
    blockSize: number;
    name: string;
    procreator;
    version: number;
    effectiveLength: number;
    shiftBits: number;
    macLength: number;
    sBox: Int8Array;
    iv: Uint8Array;
    ukm;
    multTableCalculated = this.multTable();
    /*
    algorithm
    * */
    process: (k, d, ofs: number, e: number) => void;
    keySchedule: (k: Uint8Array, e: boolean) => any; // FIXME почему???
    processMAC: (key, s, d) => void;
    keyMeshing: (k: Uint8Array, s: Uint8Array, i: number, key: Int32Array, e: boolean) => Uint8Array;
    pad: (d: Uint8Array) => Uint8Array;
    unpad: (d: Uint8Array) => Uint8Array;
    wrapKey: (kek, cek) => ArrayBufferLike;
    unwrapKey: (kek, data) => any;
    encrypt: (k, d, iv) => ArrayBufferLike;
    decrypt: (k, d, iv) => ArrayBufferLike;
    sign: (k, d, iv) => ArrayBufferLike;
    verify: (k, m, d, iv) => boolean;
    generateKey: () => {};

    /*
    * */
    defaultIV = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]);
    defaultIV128 = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    sBoxes = {
        'E-TEST': [
            0x4, 0x2, 0xF, 0x5, 0x9, 0x1, 0x0, 0x8, 0xE, 0x3, 0xB, 0xC, 0xD, 0x7, 0xA, 0x6,
            0xC, 0x9, 0xF, 0xE, 0x8, 0x1, 0x3, 0xA, 0x2, 0x7, 0x4, 0xD, 0x6, 0x0, 0xB, 0x5,
            0xD, 0x8, 0xE, 0xC, 0x7, 0x3, 0x9, 0xA, 0x1, 0x5, 0x2, 0x4, 0x6, 0xF, 0x0, 0xB,
            0xE, 0x9, 0xB, 0x2, 0x5, 0xF, 0x7, 0x1, 0x0, 0xD, 0xC, 0x6, 0xA, 0x4, 0x3, 0x8,
            0x3, 0xE, 0x5, 0x9, 0x6, 0x8, 0x0, 0xD, 0xA, 0xB, 0x7, 0xC, 0x2, 0x1, 0xF, 0x4,
            0x8, 0xF, 0x6, 0xB, 0x1, 0x9, 0xC, 0x5, 0xD, 0x3, 0x7, 0xA, 0x0, 0xE, 0x2, 0x4,
            0x9, 0xB, 0xC, 0x0, 0x3, 0x6, 0x7, 0x5, 0x4, 0x8, 0xE, 0xF, 0x1, 0xA, 0x2, 0xD,
            0xC, 0x6, 0x5, 0x2, 0xB, 0x0, 0x9, 0xD, 0x3, 0xE, 0x7, 0xA, 0xF, 0x4, 0x1, 0x8
        ],
        'E-A': [
            0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5,
            0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1,
            0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9,
            0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6,
            0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6,
            0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6,
            0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE,
            0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4
        ],
        'E-B': [
            0x8, 0x4, 0xB, 0x1, 0x3, 0x5, 0x0, 0x9, 0x2, 0xE, 0xA, 0xC, 0xD, 0x6, 0x7, 0xF,
            0x0, 0x1, 0x2, 0xA, 0x4, 0xD, 0x5, 0xC, 0x9, 0x7, 0x3, 0xF, 0xB, 0x8, 0x6, 0xE,
            0xE, 0xC, 0x0, 0xA, 0x9, 0x2, 0xD, 0xB, 0x7, 0x5, 0x8, 0xF, 0x3, 0x6, 0x1, 0x4,
            0x7, 0x5, 0x0, 0xD, 0xB, 0x6, 0x1, 0x2, 0x3, 0xA, 0xC, 0xF, 0x4, 0xE, 0x9, 0x8,
            0x2, 0x7, 0xC, 0xF, 0x9, 0x5, 0xA, 0xB, 0x1, 0x4, 0x0, 0xD, 0x6, 0x8, 0xE, 0x3,
            0x8, 0x3, 0x2, 0x6, 0x4, 0xD, 0xE, 0xB, 0xC, 0x1, 0x7, 0xF, 0xA, 0x0, 0x9, 0x5,
            0x5, 0x2, 0xA, 0xB, 0x9, 0x1, 0xC, 0x3, 0x7, 0x4, 0xD, 0x0, 0x6, 0xF, 0x8, 0xE,
            0x0, 0x4, 0xB, 0xE, 0x8, 0x3, 0x7, 0x1, 0xA, 0x2, 0x9, 0x6, 0xF, 0xD, 0x5, 0xC
        ],
        'E-C': [
            0x1, 0xB, 0xC, 0x2, 0x9, 0xD, 0x0, 0xF, 0x4, 0x5, 0x8, 0xE, 0xA, 0x7, 0x6, 0x3,
            0x0, 0x1, 0x7, 0xD, 0xB, 0x4, 0x5, 0x2, 0x8, 0xE, 0xF, 0xC, 0x9, 0xA, 0x6, 0x3,
            0x8, 0x2, 0x5, 0x0, 0x4, 0x9, 0xF, 0xA, 0x3, 0x7, 0xC, 0xD, 0x6, 0xE, 0x1, 0xB,
            0x3, 0x6, 0x0, 0x1, 0x5, 0xD, 0xA, 0x8, 0xB, 0x2, 0x9, 0x7, 0xE, 0xF, 0xC, 0x4,
            0x8, 0xD, 0xB, 0x0, 0x4, 0x5, 0x1, 0x2, 0x9, 0x3, 0xC, 0xE, 0x6, 0xF, 0xA, 0x7,
            0xC, 0x9, 0xB, 0x1, 0x8, 0xE, 0x2, 0x4, 0x7, 0x3, 0x6, 0x5, 0xA, 0x0, 0xF, 0xD,
            0xA, 0x9, 0x6, 0x8, 0xD, 0xE, 0x2, 0x0, 0xF, 0x3, 0x5, 0xB, 0x4, 0x1, 0xC, 0x7,
            0x7, 0x4, 0x0, 0x5, 0xA, 0x2, 0xF, 0xE, 0xC, 0x6, 0x1, 0xB, 0xD, 0x9, 0x3, 0x8
        ],
        'E-D': [
            0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3,
            0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1,
            0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2,
            0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8,
            0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1,
            0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6,
            0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7,
            0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE
        ],
        'E-SC': [
            0x3, 0x6, 0x1, 0x0, 0x5, 0x7, 0xd, 0x9, 0x4, 0xb, 0x8, 0xc, 0xe, 0xf, 0x2, 0xa,
            0x7, 0x1, 0x5, 0x2, 0x8, 0xb, 0x9, 0xc, 0xd, 0x0, 0x3, 0xa, 0xf, 0xe, 0x4, 0x6,
            0xf, 0x1, 0x4, 0x6, 0xc, 0x8, 0x9, 0x2, 0xe, 0x3, 0x7, 0xa, 0xb, 0xd, 0x5, 0x0,
            0x3, 0x4, 0xf, 0xc, 0x5, 0x9, 0xe, 0x0, 0x6, 0x8, 0x7, 0xa, 0x1, 0xb, 0xd, 0x2,
            0x6, 0x9, 0x0, 0x7, 0xb, 0x8, 0x4, 0xc, 0x2, 0xe, 0xa, 0xf, 0x1, 0xd, 0x5, 0x3,
            0x6, 0x1, 0x2, 0xf, 0x0, 0xb, 0x9, 0xc, 0x7, 0xd, 0xa, 0x5, 0x8, 0x4, 0xe, 0x3,
            0x0, 0x2, 0xe, 0xc, 0x9, 0x1, 0x4, 0x7, 0x3, 0xf, 0x6, 0x8, 0xa, 0xd, 0xb, 0x5,
            0x5, 0x2, 0xb, 0x8, 0x4, 0xc, 0x7, 0x1, 0xa, 0x6, 0xe, 0x0, 0x9, 0x3, 0xd, 0xf
        ],
        'E-Z': [// This is default S-box in according to draft of new standard
            0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1,
            0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf,
            0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0,
            0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb,
            0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc,
            0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0,
            0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7,
            0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2
        ],
        // S-box for digest
        'D-TEST': [
            0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3,
            0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9,
            0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB,
            0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3,
            0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2,
            0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE,
            0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC,
            0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC
        ],
        'D-A': [
            0xA, 0x4, 0x5, 0x6, 0x8, 0x1, 0x3, 0x7, 0xD, 0xC, 0xE, 0x0, 0x9, 0x2, 0xB, 0xF,
            0x5, 0xF, 0x4, 0x0, 0x2, 0xD, 0xB, 0x9, 0x1, 0x7, 0x6, 0x3, 0xC, 0xE, 0xA, 0x8,
            0x7, 0xF, 0xC, 0xE, 0x9, 0x4, 0x1, 0x0, 0x3, 0xB, 0x5, 0x2, 0x6, 0xA, 0x8, 0xD,
            0x4, 0xA, 0x7, 0xC, 0x0, 0xF, 0x2, 0x8, 0xE, 0x1, 0x6, 0x5, 0xD, 0xB, 0x9, 0x3,
            0x7, 0x6, 0x4, 0xB, 0x9, 0xC, 0x2, 0xA, 0x1, 0x8, 0x0, 0xE, 0xF, 0xD, 0x3, 0x5,
            0x7, 0x6, 0x2, 0x4, 0xD, 0x9, 0xF, 0x0, 0xA, 0x1, 0x5, 0xB, 0x8, 0xE, 0xC, 0x3,
            0xD, 0xE, 0x4, 0x1, 0x7, 0x0, 0x5, 0xA, 0x3, 0xC, 0x8, 0xF, 0x6, 0x2, 0x9, 0xB,
            0x1, 0x3, 0xA, 0x9, 0x5, 0xB, 0x4, 0xF, 0x8, 0x6, 0x7, 0xE, 0xD, 0x0, 0x2, 0xC
        ],
        'D-SC': [
            0xb, 0xd, 0x7, 0x0, 0x5, 0x4, 0x1, 0xf, 0x9, 0xe, 0x6, 0xa, 0x3, 0xc, 0x8, 0x2,
            0x1, 0x2, 0x7, 0x9, 0xd, 0xb, 0xf, 0x8, 0xe, 0xc, 0x4, 0x0, 0x5, 0x6, 0xa, 0x3,
            0x5, 0x1, 0xd, 0x3, 0xf, 0x6, 0xc, 0x7, 0x9, 0x8, 0xb, 0x2, 0x4, 0xe, 0x0, 0xa,
            0xd, 0x1, 0xb, 0x4, 0x9, 0xc, 0xe, 0x0, 0x7, 0x5, 0x8, 0xf, 0x6, 0x2, 0xa, 0x3,
            0x2, 0xd, 0xa, 0xf, 0x9, 0xb, 0x3, 0x7, 0x8, 0xc, 0x5, 0xe, 0x6, 0x0, 0x1, 0x4,
            0x0, 0x4, 0x6, 0xc, 0x5, 0x3, 0x8, 0xd, 0xa, 0xb, 0xf, 0x2, 0x1, 0x9, 0x7, 0xe,
            0x1, 0x3, 0xc, 0x8, 0xa, 0x6, 0xb, 0x0, 0x2, 0xe, 0x7, 0x9, 0xf, 0x4, 0x5, 0xd,
            0xa, 0xb, 0x6, 0x0, 0x1, 0x3, 0x4, 0x7, 0xe, 0xd, 0x5, 0xf, 0x8, 0x2, 0x9, 0xc
        ]
    };
    // 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
    kB = [4, 2, 3, 1, 6, 5, 0, 7, 0, 5, 6, 1, 3, 2, 4, 0];

    C = new Uint8Array([
        0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
        0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
        0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
        0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B
    ]);
    // Nonlinear transformation
    kPi = [
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
        233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
        249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
        5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
        235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
        181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
        21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
        50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
        223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
        224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
        167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
        173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
        7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
        225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
        32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
        89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
    ];
    Uint16Array;

    constructor(public gostRandom: GostRandom, public algorithm: AlgorithmIndentifier) {

        // Check little endian support
        if (!this.littleEndian()) {
            throw new Error('Big endian platform not supported');
        }

        this.keySize = 32;
        this.blockLength = algorithm.length || 64;
        this.blockSize = this.blockLength >> 3;

        this.name = (algorithm.name || (algorithm.version === 1 ? 'RC2' :
            algorithm.version === 1989 ? 'GOST 28147' : 'GOST R 34.12')) +
            (algorithm.version > 4 ? '-' + ((algorithm.version || 1989) % 100) : '') + '-' +
            (this.blockLength === 64 ? '' : this.blockLength + '-') +
            ((algorithm.mode === 'MAC') ? 'MAC-' + (algorithm.macLength || this.blockLength >> 1) :
                (algorithm.mode === 'KW' || algorithm.keyWrapping) ?
                    ((algorithm.keyWrapping || 'NO') !== 'NO' ? algorithm.keyWrapping : '') + 'KW' :
                    (algorithm.block || 'ECB') + ((algorithm.block === 'CFB' || algorithm.block === 'OFB' ||
                    (algorithm.block === 'CTR' && algorithm.version === 2015)) &&
                    algorithm.shiftBits && algorithm.shiftBits !== this.blockLength ? '-' + algorithm.shiftBits : '') +
                    (algorithm.padding ? '-' + (algorithm.padding || (algorithm.block === 'CTR' ||
                    algorithm.block === 'CFB' || algorithm.block === 'OFB' ? 'NO' : 'ZERO')) + 'PADDING' : '') +
                    ((algorithm.keyMeshing || 'NO') !== 'NO' ? '-CPKEYMESHING' : '')) +
            (algorithm.procreator ? '/' + algorithm.procreator : '') +
            (typeof algorithm.sBox === 'string' ? '/' + algorithm.sBox : '');

        // Algorithm procreator
        this.procreator = algorithm.procreator;

        switch (algorithm.version || 1989) {
            case 1:
                this.process = this.processRC2;
                this.keySchedule = this.keyScheduleRC2;
                this.blockLength = 64;
                this.effectiveLength = algorithm.length || 32;
                this.keySize = 8 * Math.ceil(this.effectiveLength / 8); // Max 128
                this.blockSize = this.blockLength >> 3;
                break;
            case 2015:
                this.version = 2015;
                if (this.blockLength === 64) {
                    this.process = this.process15;
                    this.keySchedule = this.keySchedule15;
                } else if (this.blockLength === 128) {
                    this.process = this.process128;
                    this.keySchedule = this.keySchedule128;
                } else {
                    throw new Error('Invalid block length');
                }
                this.processMAC = this.processMAC15;
                break;
            case 1989:
                this.version = 1989;
                this.process = this.process89;
                this.processMAC = this.processMAC89;
                this.keySchedule = this.keySchedule89;
                if (this.blockLength !== 64) {
                    throw new Error('Invalid block length');
                }
                break;
            default:
                throw new Error('Algorithm version ' + algorithm.version + ' not supported');
        }

        switch (algorithm.mode || (algorithm.keyWrapping && 'KW') || 'ES') {

            case 'ES':
                switch (algorithm.block || 'ECB') {
                    case 'ECB':
                        this.encrypt = this.encryptECB;
                        this.decrypt = this.decryptECB;
                        break;
                    case 'CTR':
                        if (this.version === 1989) {
                            this.encrypt = this.processCTR89;
                            this.decrypt = this.processCTR89;
                        } else {
                            this.encrypt = this.processCTR15;
                            this.decrypt = this.processCTR15;
                            this.shiftBits = algorithm.shiftBits || this.blockLength;
                        }
                        break;
                    case 'CBC':
                        this.encrypt = this.encryptCBC;
                        this.decrypt = this.decryptCBC;
                        break;
                    case 'CFB':
                        this.encrypt = this.encryptCFB;
                        this.decrypt = this.decryptCFB;
                        this.shiftBits = algorithm.shiftBits || this.blockLength;
                        break;
                    case 'OFB':
                        this.encrypt = this.processOFB;
                        this.decrypt = this.processOFB;
                        this.shiftBits = algorithm.shiftBits || this.blockLength;
                        break;
                    default:
                        throw new Error('Block mode ' + algorithm.block + ' not supported');
                }
                switch (algorithm.keyMeshing) {
                    case 'CP':
                        this.keyMeshing = this.keyMeshingCP;
                        break;
                    default:
                        this.keyMeshing = this.noKeyMeshing;
                }
                if (this.encrypt === this.encryptECB || this.encrypt === this.encryptCBC) {
                    switch (algorithm.padding) {
                        case 'PKCS5P':
                            this.pad = this.pkcs5Pad;
                            this.unpad = this.pkcs5Unpad;
                            break;
                        case 'RANDOM':
                            this.pad = this.randomPad;
                            this.unpad = this.noPad;
                            break;
                        case 'BIT':
                            this.pad = this.bitPad;
                            this.unpad = this.bitUnpad;
                            break;
                        default:
                            this.pad = this.zeroPad;
                            this.unpad = this.noPad;
                    }
                } else {
                    this.pad = this.noPad;
                    this.unpad = this.noPad;
                }
                this.generateKey = this.generateKeyDefault;
                break;
            case 'MAC':
                this.sign = this.signMAC;
                this.verify = this.verifyMAC;
                this.generateKey = this.generateKeyDefault;
                this.macLength = algorithm.macLength || (this.blockLength >> 1);
                this.pad = this.noPad;
                this.unpad = this.noPad;
                this.keyMeshing = this.noKeyMeshing;
                break;
            case 'KW':
                this.pad = this.noPad;
                this.unpad = this.noPad;
                this.keyMeshing = this.noKeyMeshing;
                switch (algorithm.keyWrapping) {
                    case 'CP':
                        this.wrapKey = this.wrapKeyCP;
                        this.unwrapKey = this.unwrapKeyCP;
                        this.generateKey = this.generateKeyDefault;
                        this.shiftBits = algorithm.shiftBits || this.blockLength;
                        break;
                    case 'SC':
                        this.wrapKey = this.wrapKeySC;
                        this.unwrapKey = this.unwrapKeySC;
                        this.generateKey = this.generateWrappingKeySC;
                        break;
                    default:
                        this.wrapKey = this.wrapKeyGOST;
                        this.unwrapKey = this.unwrapKeyGOST;
                        this.generateKey = this.generateKeyDefault;
                }
                break;
            case 'MASK':
                this.wrapKey = this.wrapKeyMask;
                this.unwrapKey = this.unwrapKeyMask;
                this.generateKey = this.generateKeyDefault;
                break;
            default:
                throw new Error('Mode ' + algorithm.mode + ' not supported');
        }

        // Define sBox parameter
        let sBox = algorithm.sBox;
        let sBoxName;
        if (!sBox) {
            sBox = this.version === 2015 ? this.sBoxes['E-Z'] : this.procreator === 'SC' ? this.sBoxes['E-SC'] : this.sBoxes['E-A'];
        } else if (typeof sBox === 'string') {
            sBoxName = sBox.toUpperCase();
            sBox = this.sBoxes[sBoxName];
            if (!sBox) {
                throw new Error('Unknown sBox name: ' + algorithm.sBox);
            }
        } else if (!sBox.length || sBox.length !== this.sBoxes['E-Z'].length) {
            throw new Error('Length of sBox must be ' + this.sBoxes['E-Z'].length);
        }
        this.sBox = sBox;
        // Initial vector
        if (algorithm.iv) {
            this.iv = new Uint8Array(algorithm.iv);
            if (this.iv.byteLength !== this.blockSize && this.version === 1989) {
                throw new Error('Length of iv must be ' + this.blockLength + ' bits');
            } else if (this.iv.byteLength !== this.blockSize >> 1 && this.encrypt === this.processCTR15) {
                throw new Error('Length of iv must be ' + (this.blockLength >> 1) + ' bits');
            } else if (this.iv.byteLength % this.blockSize !== 0 && this.encrypt !== this.processCTR15) {
                throw new Error('Length of iv must be a multiple of ' + this.blockLength + ' bits');
            }
        } else {
            this.iv = this.blockLength === 128 ? this.defaultIV128 : this.defaultIV;
        }
        // User key material
        if (algorithm.ukm) {
            this.ukm = new Uint8Array(algorithm.ukm);
            if (this.ukm.byteLength * 8 !== this.blockLength) {
                throw new Error('Length of ukm must be ' + this.blockLength + ' bits');
            }
        }
    }

    public littleEndian(): boolean {
        const buffer = new ArrayBuffer(2);
        new DataView(buffer).setInt16(0, 256, true);
        return new Int16Array(buffer)[0] === 256;
    }

    public signed(x): number {
        return x >= 0x80000000 ? x - 0x100000000 : x;
    }

    public unsigned(x): number {
        return x < 0 ? x + 0x100000000 : x;
    }


    public randomSeed(randonArray): void {
        this.gostRandom.getRandomValues(randonArray);
    }




    public byteArray(d: Uint8Array): Uint8Array {
        return new Uint8Array(GostCoding.buffer(d));
    }

    public cloneArray(d: Uint8Array) {
        return new Uint8Array(this.byteArray(d));
    }

    public intArray(d: Uint8Array): Int32Array {
        return new Int32Array(GostCoding.buffer(d));
    }

    public swap32(b: number): number { // FixMe уточнить тип

        return ((b & 0xff) << 24) | ((b & 0xff00) << 8) | ((b >> 8) & 0xff00) | ((b >> 24) & 0xff);
    }

    public multTable(): number[][] {
        // Multiply two numbers in the GF(2^8) finite field defined
        // by the polynomial x^8 + x^7 + x^6 + x + 1 = 0 */
        function gmul(a, b) {
            let p = 0;
            let counter;
            let carry;
            for (counter = 0; counter < 8; counter++) {
                if (b & 1) {
                    p ^= a;
                }
                carry = a & 0x80; // detect if x^8 term is about to be generated
                a = (a << 1) & 0xff;
                if (carry) {
                    a ^= 0xc3;
                } // replace x^8 with x^7 + x^6 + x + 1
                b >>= 1;
            }
            return p & 0xff;
        }
        // It is required only this values for R function
        //       0   1   2    3    4    5    6    7
        const x = [1, 16, 32, 133, 148, 192, 194, 251];
        const m = [];
        for (let i = 0; i < 8; i++) {
            m[i] = [];
            for (let j = 0; j < 256; j++) {
                m[i][j] = gmul(x[i], j);
            }
        }
        return m;
    }

    funcR(d): void {
        let sum = 0;
        for (let i = 0; i < 16; i++) {

            sum ^= this.multTableCalculated[this.kB[i]][d[i]];
        }

        for (let i = 16; i > 0; --i) {
            d[i] = d[i - 1];
        }
        d[0] = sum;
    }

    funcReverseR(d: number[]): void {
        const tmp = d[0];
        for (let i = 0; i < 15; i++) {
            d[i] = d[i + 1];
        }
        d[15] = tmp;

        let sum = 0;
        for (let i = 0; i < 16; i++) {

            sum ^= this.multTableCalculated[this.kB[i]][d[i]];
        }
        d[15] = sum;
    }

    kReversePi(): number[] {
        const m = [];
        for (let i = 0, n = this.kPi.length; i < n; i++) {
            m[this.kPi[i]] = i;
        }
        return m;
    }

    funcS(d): void {
        for (let i = 0; i < 16; ++i) {
            d[i] = this.kPi[d[i]];
        }
    }

    funcReverseS(d): void {
        for (let i = 0; i < 16; ++i) {
            d[i] = this.kReversePi[d[i]];
        }
    }

    funcX(a, b): void {
        for (let i = 0; i < 16; ++i) {

            a[i] ^= b[i];
        }
    }

    funcL(d): void {
        for (let i = 0; i < 16; ++i) {
            this.funcR(d);
        }
    }

    funcReverseL(d): void {
        for (let i = 0; i < 16; ++i) {
            this.funcReverseR(d);
        }
    }

    funcLSX(a, b): void {
        this.funcX(a, b);
        this.funcS(a);
        this.funcL(a);
    }

    funcReverseLSX(a, b): void {
        this.funcX(a, b);
        this.funcReverseL(a);
        this.funcReverseS(a);
    }

    funcF(inputKey, inputKeySecond, iterationConst): void {
        const tmp = new Uint8Array(inputKey);
        this.funcLSX(inputKey, iterationConst);
        this.funcX(inputKey, inputKeySecond);
        inputKeySecond.set(tmp);
    }

    funcC(n, d): void {
        for (let i = 0; i < 15; i++) {
            d[i] = 0;
        }
        d[15] = n;
        this.funcL(d);
    }

    /**
     * Key schedule for GOST R 34.12-15 128bits
     */
    keySchedule128(k: Uint8Array, ignored): Uint8Array {
        const keys = new Uint8Array(160);
        const c = new Uint8Array(16);
        keys.set(this.byteArray(k));
        for (let j = 0; j < 4; j++) {
            const j0 = 32 * j;
            const j1 = 32 * (j + 1);
            keys.set(new Uint8Array(keys.buffer, j0, 32), j1);
            for (let i = 1; i < 9; i++) {
                this.funcC(j * 8 + i, c);
                this.funcF(new Uint8Array(keys.buffer, j1, 16),
                    new Uint8Array(keys.buffer, j1 + 16, 16), c);
            }
        }
        return keys;
    }

    /**
     * GOST R 34.12-15 128 bits encrypt/decrypt process
     */
    process128(k: Uint8Array, d: Uint8Array, ofs: number, e: number): void {
        ofs = ofs || d.byteOffset;
        const r = new Uint8Array(d.buffer, ofs, 16);
        if (e) {
            for (let i = 0; i < 9; i++) {
                this.funcReverseLSX(r, new Uint8Array(k.buffer, (9 - i) * 16, 16));
            }

            this.funcX(r, new Uint8Array(k.buffer, 0, 16));
        } else {
            for (let i = 0; i < 9; i++) {
                this.funcLSX(r, new Uint8Array(k.buffer, 16 * i, 16));
            }
            this.funcX(r, new Uint8Array(k.buffer, 16 * 9, 16));
        }
    }

    /**
     * One GOST encryption round
     */
    round(s: Int8Array, m: Int32Array, k: number): void {

        let cm = (m[0] + k) & 0xffffffff;


        let om = s[0 + ((cm >> (0 * 4)) & 0xF)] << (0 * 4);

        om |= s[16 + ((cm >> (1 * 4)) & 0xF)] << (1 * 4);

        om |= s[32 + ((cm >> (2 * 4)) & 0xF)] << (2 * 4);

        om |= s[48 + ((cm >> (3 * 4)) & 0xF)] << (3 * 4);

        om |= s[64 + ((cm >> (4 * 4)) & 0xF)] << (4 * 4);

        om |= s[80 + ((cm >> (5 * 4)) & 0xF)] << (5 * 4);

        om |= s[96 + ((cm >> (6 * 4)) & 0xF)] << (6 * 4);

        om |= s[112 + ((cm >> (7 * 4)) & 0xF)] << (7 * 4);

        cm = om << 11 | om >>> (32 - 11);

        cm ^= m[1];
        m[1] = m[0];
        m[0] = cm;
    }

    process89(k: Int32Array, d: Int32Array, ofs: number): void {
        ofs = ofs || d.byteOffset;
        const s = this.sBox;
        const m = new Int32Array(d.buffer, ofs, 2);

        for (let i = 0; i < 32; i++) {
            this.round(s, m, k[i]);
        }

        const r = m[0];
        m[0] = m[1];
        m[1] = r;
    }

    /**
     * Process encrypt/decrypt block with key K using GOST R 34.12-15 64bit block
     */
    process15(k: Int32Array, d: Int32Array, ofs: number): void {
        ofs = ofs || d.byteOffset;
        const s = this.sBox;
        const m = new Int32Array(d.buffer, ofs, 2);
        const r = this.swap32(m[0]);
        m[0] = this.swap32(m[1]);
        m[1] = r;

        for (let i = 0; i < 32; i++) {
            this.round(s, m, k[i]);
        }

        m[0] = this.swap32(m[0]);
        m[1] = this.swap32(m[1]);
    }

    keySchedule89(k: Uint8Array, e: boolean): Int32Array {
        const sch = new Int32Array(32);
        const key = new Int32Array(GostCoding.buffer(k));
        for (let i = 0; i < 8; i++) {
            sch[i] = key[i];
        }
        if (e) {
            for (let i = 0; i < 8; i++) {
                sch[i + 8] = sch[7 - i];
            }
            for (let i = 0; i < 8; i++) {
                sch[i + 16] = sch[7 - i];
            }
        } else {
            for (let i = 0; i < 8; i++) {
                sch[i + 8] = sch[i];
            }

            for (let i = 0; i < 8; i++) {
                sch[i + 16] = sch[i];
            }
        }
        for (let i = 0; i < 8; i++) {
            sch[i + 24] = sch[7 - i];
        }
        return sch;
    }

    /**
     * Key keySchedule algorithm for GOST R 34.12-15 64bit cipher
     */
    keySchedule15(k: Uint8Array, e: boolean): Int32Array {
        const sch = new Int32Array(32);
        const key = new Int32Array(GostCoding.buffer(k));
        for (let i = 0; i < 8; i++) {
            sch[i] = this.swap32(key[i]);
        }
        if (e) {
            for (let i = 0; i < 8; i++) {
                sch[i + 8] = sch[7 - i];
            }
            for (let i = 0; i < 8; i++) {
                sch[i + 16] = sch[7 - i];
            }
        } else {
            for (let i = 0; i < 8; i++) {
                sch[i + 8] = sch[i];
            }
            for (let i = 0; i < 8; i++) {
                sch[i + 16] = sch[i];
            }
        }
        for (let i = 0; i < 8; i++) {
            sch[i + 24] = sch[7 - i];
        }
        return sch;
    }

    /**
     * Key schedule for RC2
     */
    keyScheduleRC2(k: Uint8Array, ignored: boolean): Uint16Array {
        // an array of "random" bytes based on the digits of PI = 3.14159...


        const PITABLE = new Uint8Array([
            0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
            0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
            0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
            0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
            0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
            0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
            0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
            0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
            0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
            0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
            0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
            0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
            0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
            0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
            0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
            0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
        ]);
        const key = new Uint8Array(GostCoding.buffer(k));
        const T = Math.min(key.length, 128);
        const T1 = this.effectiveLength;
        const T8 = Math.floor((T1 + 7) / 8);
        const TM = 0xff % Math.pow(2, 8 + T1 - 8 * T8);

        const L = new Uint8Array(128);
        const returnK = new Uint16Array(L.buffer);
        for (let i = 0; i < T; i++) {
            L[i] = key[i];
        }
        for (let i = T; i < 128; i++) {
            L[i] = PITABLE[(L[i - 1] + L[i - T]) % 256];
        }

        L[128 - T8] = PITABLE[L[128 - T8] & TM];

        for (let i = 127 - T8; i >= 0; --i) {

            L[i] = PITABLE[L[i + 1] ^ L[i + T8]];
        }
        return returnK;
    }

    /**
     * RC2 encrypt/decrypt process
     */
    processRC2(k, d, ofs: number, e: number) {
        let K;
        let j;
        let R = new Uint16Array(4);
        const s = new Uint16Array([1, 2, 3, 5]);
        // tslint:disable-next-line:no-shadowed-variable
        const reverse = e;
        //  1. Initialize words R[0], ..., R[3] to contain the 64-bit
        //     ciphertext value.
        R = new Uint16Array(d.buffer, ofs || d.byteOffset, 4);
        //  2. Expand the key, so that words K[0], ..., K[63] become
        //     defined.
        K = k;
        //  3. Initialize j to zero (enc) j to 63 (dec).
        j = e ? 63 : 0;
        //  4. Perform five mixing rounds.
        perform(mix, 5);
        //  5. Perform one mashing round.
        perform(mash, 1);
        //  6. Perform six mixing rounds.
        perform(mix, 6);
        //  7. Perform one mashing round.
        perform(mash, 1);
        //  8. Perform five mixing rounds.
        perform(mix, 5);


        function rol(R, s) {
            return (R << s | R >>> (16 - s)) & 0xffff;
        }

        function ror(R, s) {
            return (R >>> s | R << (16 - s)) & 0xffff;
        }

        function mix(i) {
            if (reverse) {
                R[i] = ror(R[i], s[i]);
                R[i] = R[i] - K[j] - (R[(i + 3) % 4] & R[(i + 2) % 4]) - ((~R[(i + 3) % 4]) & R[(i + 1) % 4]);
                j = j - 1;
            } else {
                R[i] = R[i] + K[j] + (R[(i + 3) % 4] & R[(i + 2) % 4]) + ((~R[(i + 3) % 4]) & R[(i + 1) % 4]);
                j = j + 1;
                R[i] = rol(R[i], s[i]);
            }
        }

        function mash(i) {
            if (reverse) {
                R[i] = R[i] - K[R[(i + 3) % 4] & 63];
            } else {
                R[i] = R[i] + K[R[(i + 3) % 4] & 63];
            }
        }

        function perform(method, count) {
            count = count || 1;
            for (let j = 0; j < count; j++) {
                if (reverse) {
                    for (let i = 3; i >= 0; --i) {
                        method(i);
                    }
                } else {
                    for (let i = 0; i < 4; i++) {
                        method(i);
                    }
                }
            }
        }
    }

    /**
     * Algorithm name GOST 28147-ECB
     */
    encryptECB(k: Uint8Array, d: Uint8Array): ArrayBufferLike {
        const p = this.pad(this.byteArray(d));
        const n = this.blockSize;
        const b = p.byteLength / n;
        const key = this.keySchedule(k, undefined);

        for (let i = 0; i < b; i++) {
            this.process(key, p, n * i, undefined);
        }

        return p.buffer;
    }

    /**
     * Algorithm name GOST 28147-ECB<br><br>
     */
    decryptECB(k: Uint8Array, d: Uint8Array): ArrayBufferLike {
        const p = this.cloneArray(d);
        const n = this.blockSize;
        const b = p.byteLength / n;
        const key = this.keySchedule(k, true);

        for (let i = 0; i < b; i++) {
            this.process(key, p, n * i, 1);
        }

        return this.unpad(p).buffer;
    }

    /**
     * Algorithm name GOST 28147-CFB
     */
    encryptCFB(k, d, iv) {
        const s = new Uint8Array(iv || this.iv);
        let c = this.cloneArray(d);
        let m = s.length;
        let t = new Uint8Array(m);
        let b = this.shiftBits >> 3;
        let cb = c.length;
        let r = cb % b;
        let q = (cb - r) / b;

        const key = this.keySchedule(k, undefined);

        for (let i = 0; i < q; i++) {

            for (let j = 0; j < m; j++) {
                t[j] = s[j];
            }

            this.process(key, s, undefined, undefined);

            for (let j = 0; j < b; j++) {
                c[i * b + j] ^= s[j];
            }

            for (let j = 0; j < m - b; j++) {
                s[j] = t[b + j];
            }

            for (let j = 0; j < b; j++) {
                s[m - b + j] = c[i * b + j];
            }

            k = this.keyMeshing(k, s, i, key, undefined);
        }

        if (r > 0) {
            this.process(key, s, undefined, undefined);

            for (let i = 0; i < r; i++) {
                c[q * b + i] ^= s[i];
            }
        }
        return c.buffer;
    }

    /**
     * Algorithm name GOST 28147-CFB<br><br>
     */
    decryptCFB(k, d, iv) {
        let s = new Uint8Array(iv || this.iv);
        let c = this.cloneArray(d);
        let m = s.length;
        let t = new Uint8Array(m);
        let b = this.shiftBits >> 3;
        let cb = c.length;
        let r = cb % b;
        let q = (cb - r) / b;
        let key = this.keySchedule(k, undefined);

        for (let i = 0; i < q; i++) {

            for (let j = 0; j < m; j++) {
                t[j] = s[j];
            }

            this.process(key, s, undefined, undefined);

            for (let j = 0; j < b; j++) {
                t[j] = c[i * b + j];
                c[i * b + j] ^= s[j];
            }

            for (let j = 0; j < m - b; j++) {
                s[j] = t[b + j];
            }

            for (let j = 0; j < b; j++) {
                s[m - b + j] = t[j];
            }

            k = this.keyMeshing(k, s, i, key, undefined);
        }

        if (r > 0) {
            this.process(key, s, undefined, undefined);

            for (let i = 0; i < r; i++) {
                c[q * b + i] ^= s[i];
            }
        }
        return c.buffer;
    }

    processOFB(k, d, iv): ArrayBufferLike {
        let s = new Uint8Array(iv || this.iv);
        let c = this.cloneArray(d);
        let m = s.length;
        let t = new Uint8Array(m);
        let b = this.shiftBits >> 3;
        let p = new Uint8Array(b);
        let cb = c.length;
        let r = cb % b;
        let q = (cb - r) / b;
        let key = this.keySchedule(k, undefined);

        for (let i = 0; i < q; i++) {

            for (let j = 0; j < m; j++) {
                t[j] = s[j];
            }

            this.process(key, s, undefined, undefined);

            for (let j = 0; j < b; j++) {
                p[j] = s[j];
            }

            for (let j = 0; j < b; j++) {
                c[i * b + j] ^= s[j];
            }

            for (let j = 0; j < m - b; j++) {
                s[j] = t[b + j];
            }

            for (let j = 0; j < b; j++) {
                s[m - b + j] = p[j];
            }

            k = this.keyMeshing(k, s, i, key, undefined);
        }

        if (r > 0) {
            this.process(key, s, undefined, undefined);

            for (let i = 0; i < r; i++) {
                c[q * b + i] ^= s[i];
            }
        }
        return c.buffer;
    }

    processCTR89(k, d, iv): ArrayBufferLike {
        let s = new Uint8Array(iv || this.iv);
        let c = this.cloneArray(d);
        let b = this.blockSize;
        let t = new Int8Array(b);
        let cb = c.length;
        let r = cb % b;
        let q = (cb - r) / b;
        let key = this.keySchedule(k, undefined);
        let syn = new Int32Array(s.buffer);

        this.process(key, s, undefined, undefined);

        for (let i = 0; i < q; i++) {
            syn[0] = (syn[0] + 0x1010101) & 0xffffffff;
            // syn[1] = signed(unsigned((syn[1] + 0x1010104) & 0xffffffff) % 0xffffffff);
            let tmp = this.unsigned(syn[1]) + 0x1010104; // Special thanks to Ilya Matveychikov
            syn[1] = this.signed(tmp < 0x100000000 ? tmp : tmp - 0xffffffff);

            for (let j = 0; j < b; j++) {
                t[j] = s[j];
            }

            this.process(key, syn, undefined, undefined);

            for (let j = 0; j < b; j++) {
                c[i * b + j] ^= s[j];
            }

            for (let j = 0; j < b; j++) {
                s[j] = t[j];
            }

            k = this.keyMeshing(k, s, i, key, undefined);
        }
        if (r > 0) {
            syn[0] = (syn[0] + 0x1010101) & 0xffffffff;
            // syn[1] = signed(unsigned((syn[1] + 0x1010104) & 0xffffffff) % 0xffffffff);
            let tmp = this.unsigned(syn[1]) + 0x1010104; // Special thanks to Ilya Matveychikov
            syn[1] = this.signed(tmp < 0x100000000 ? tmp : tmp - 0xffffffff);

            this.process(key, syn, undefined, undefined);

            for (let i = 0; i < r; i++) {
                c[q * b + i] ^= s[i];
            }
        }
        return c.buffer;
    }

    processCTR15(k, d, iv): ArrayBufferLike {
        let c = this.cloneArray(d);
        let n = this.blockSize;
        let b = this.shiftBits >> 3;
        let cb = c.length;
        let r = cb % b;
        let q = (cb - r) / b;
        let s = new Uint8Array(n);
        let t = new Int32Array(n);
        let key = this.keySchedule(k, undefined);

        s.set(iv || this.iv);
        for (let i = 0; i < q; i++) {

            for (let j = 0; j < n; j++) {
                t[j] = s[j];
            }

            this.process(key, s, undefined, undefined);

            for (let j = 0; j < b; j++) {
                c[b * i + j] ^= s[j];
            }

            for (let j = 0; j < n; j++) {
                s[j] = t[j];
            }

            for (let j = n - 1; i >= 0; --i) {
                if (s[j] > 0xfe) {
                    s[j] -= 0xfe;
                } else {
                    s[j]++;
                    break;
                }
            }
        }

        if (r > 0) {
            this.process(key, s, undefined, undefined);
            for (let j = 0; j < r; j++) {
                c[b * q + j] ^= s[j];
            }
        }

        return c.buffer;
    }

    encryptCBC(k, d, iv): ArrayBufferLike {
        let s = new Uint8Array(iv || this.iv);
        let n = this.blockSize;
        let m = s.length;
        let c = this.pad(this.byteArray(d));
        let key = this.keySchedule(k, undefined);

        for (let i = 0, b = c.length / n; i < b; i++) {

            for (let j = 0; j < n; j++) {
                s[j] ^= c[i * n + j];
            }

            this.process(key, s, undefined, undefined);

            for (let j = 0; j < n; j++) {
                c[i * n + j] = s[j];
            }

            if (m !== n) {
                for (let j = 0; j < m - n; j++) {
                    s[j] = s[n + j];
                }

                for (let j = 0; j < n; j++) {
                    s[j + m - n] = c[i * n + j];
                }
            }

            k = this.keyMeshing(k, s, i, key, undefined);
        }

        return c.buffer;
    }

    decryptCBC(k, d, iv): ArrayBufferLike {
        let s = new Uint8Array(iv || this.iv);
        let n = this.blockSize;
        let m = s.length;
        let c = this.cloneArray(d);
        let next = new Uint8Array(n);
        let key = this.keySchedule(k, true);

        for (let i = 0, b = c.length / n; i < b; i++) {

            for (let j = 0; j < n; j++) {
                next[j] = c[i * n + j];
            }

            this.process(key, c, i * n, 1);

            for (let j = 0; j < n; j++) {
                c[i * n + j] ^= s[j];
            }

            if (m !== n) {
                for (let j = 0; j < m - n; j++) {
                    s[j] = s[n + j];
                }
            }

            for (let j = 0; j < n; j++) {
                s[j + m - n] = next[j];
            }

            k = this.keyMeshing(k, s, i, key, true);
        }

        return this.unpad(c).buffer;
    }

    generateKeyDefault(): ArrayBufferLike {
        // Simple generate 256 bit random seed
        const k = new Uint8Array(this.keySize);
        this.randomSeed(k);
        return k.buffer;
    }

    processMAC89(key, s, d) {
        let c = this.zeroPad.call(this, this.byteArray(d)); // FixMe
        let n = this.blockSize;
        let q = c.length / n;
        let sBox = this.sBox;
        let sum = new Int32Array(s.buffer);

        for (let i = 0; i < q; i++) {

            for (let j = 0; j < n; j++) {
                s[j] ^= c[i * n + j];
            }

            for (let j = 0; j < 16; j++) { // 1-16 steps
                this.round(sBox, sum, key[j]);
            }
        }
    }

    processKeyMAC15(s) {
        let t = 0;
        let n = s.length;
        for (let i = n - 1; i >= 0; --i) {
            let t1 = s[i] >>> 7;
            s[i] = (s[i] << 1) & 0xff | t;
            t = t1;
        }
        if (t !== 0) {
            if (n === 16) {
                s[15] ^= 0x87;
            } else {
                s[7] ^= 0x1b;
            }
        }
    }

    processMAC15(key, s, d) {
        let n = this.blockSize;
        let sBox = this.sBox;
        let c = this.byteArray(d);
        let r = new Uint8Array(n);
        // R
        this.process(key, r, undefined, undefined);
        // K1
        this.processKeyMAC15(r);
        if (d.byteLength % n !== 0) {
            c = this.bitPad.call(this, this.byteArray(d));
            // K2
            this.processKeyMAC15(r);
        }

        for (let i = 0, q = c.length / n; i < q; i++) {

            for (let j = 0; j < n; j++) {
                s[j] ^= c[i * n + j];
            }

            if (i === q - 1) {// Last block
                for (let j = 0; j < n; j++) {
                    s[j] ^= r[j];
                }
            }

            this.process(key, s, undefined, undefined);
        }
    }

    signMAC(k, d, iv) {
        let key = this.keySchedule(k, undefined);
        let s = new Uint8Array(iv || this.iv);
        let m = Math.ceil(this.macLength >> 3) || this.blockSize >> 1;

        this.processMAC(key, s, d);

        let mac = new Uint8Array(m); // mac size
        mac.set(new Uint8Array(s.buffer, 0, m));
        return mac.buffer;
    }

    verifyMAC(k, m, d, iv): boolean {
        let mac = new Uint8Array(this.signMAC(k, d, iv));
        let test = this.byteArray(m);
        if (mac.length !== test.length) {
            return false;
        }
        for (let i = 0, n = mac.length; i < n; i++) {
            if (mac[i] !== test[i]) {
                return false;
            }
        }
        return true;
    }

    wrapKeyGOST(kek, cek) {
        let n = this.blockSize;
        let k = this.keySize;
        let len = k + (n >> 1);
        // 1) For a unique symmetric KEK, generate 8 octets at random and call
        // the result UKM.  For a KEK, produced by VKO GOST R 34.10-2001, use
        // the UKM that was used for key derivation.
        if (!this.ukm) {
            throw new Error('UKM must be defined');
        }
        let ukm = new Uint8Array(this.ukm);
        // 2) Compute a 4-byte checksum value, GOST 28147IMIT (UKM, KEK, CEK).
        // Call the result CEK_MAC.
        let mac = this.signMAC( kek, cek, ukm);
        // 3) Encrypt the CEK in ECB mode using the KEK.  Call the ciphertext CEK_ENC.
        let enc = this.encryptECB.call(this, kek, cek);
        // 4) The wrapped content-encryption key is (UKM | CEK_ENC | CEK_MAC).
        let r = new Uint8Array(len);
        r.set(new Uint8Array(enc), 0);
        r.set(new Uint8Array(mac), k);
        return r.buffer;
    }

    unwrapKeyGOST(kek, data) {
        let n = this.blockSize;
        let k = this.keySize;
        let len = k + (n >> 1);
        // 1) If the wrapped content-encryption key is not 44 octets, then error.
        let d = GostCoding.buffer(data);
        if (d.byteLength !== len) {
            throw new Error('Wrapping key size must be ' + len + ' bytes');
        }
        // 2) Decompose the wrapped content-encryption key into UKM, CEK_ENC, and CEK_MAC.
        // UKM is the most significant (first) 8 octets. CEK_ENC is next 32 octets,
        // and CEK_MAC is the least significant (last) 4 octets.
        if (!this.ukm) {
            throw new Error('UKM must be defined');
        }
        let ukm = new Uint8Array(this.ukm);
        let enc = new Uint8Array(d, 0, k);
        let mac = new Uint8Array(d, k, n >> 1);
        // 3) Decrypt CEK_ENC in ECB mode using the KEK.  Call the output CEK.
        let cek = this.decryptECB.call(this, kek, enc);
        // 4) Compute a 4-byte checksum value, GOST 28147IMIT (UKM, KEK, CEK),
        // compare the result with CEK_MAC.  If they are not equal, then error.
        let check = this.verifyMAC.call(this, kek, mac, cek, ukm);
        if (!check) {
            throw new Error('Error verify MAC of wrapping key');
        }
        return cek;
    }

    /**
     * Algorithm name GOST 28147-CPKW<br><br>
     *
     * Given a random 64-bit UKM and a GOST 28147 key K, this algorithm
     * creates a new GOST 28147-89 key K(UKM).
     * Ref. rfc4357 6.3 CryptoPro KEK Diversification Algorithm
     * @param kek Key encryption key
     * @param ukm Random generated value
     * @returns CryptoOperationData Diversified kek
     */
    diversifyKEK(kek: Uint8Array, ukm: Uint8Array): Int32Array {
        let n = this.blockSize;

        // 1) Let K[0] = K;
        let k = this.intArray(kek);
        // 2) UKM is split into components a[i,j]:
        //    UKM = a[0]|..|a[7] (a[i] - byte, a[i,0]..a[i,7] - it’s bits)
        let a = [];
        for (let i = 0; i < n; i++) {
            a[i] = [];
            for (let j = 0; j < 8; j++) {
                a[i][j] = (ukm[i] >>> j) & 0x1;
            }
        }
        // 3) Let i be 0.
        // 4) K[1]..K[8] are calculated by repeating the following algorithm
        //    eight times:
        for (let i = 0; i < n; i++) {
            //     A) K[i] is split into components k[i,j]:
            //        K[i] = k[i,0]|k[i,1]|..|k[i,7] (k[i,j] - 32-bit integer)
            //     B) Vector S[i] is calculated:
            //        S[i] = ((a[i,0]*k[i,0] + ... + a[i,7]*k[i,7]) mod 2^32) |
            //         (((~a[i,0])*k[i,0] + ... + (~a[i,7])*k[i,7]) mod 2^32);
            let s = new Int32Array(2);
            for (let j = 0; j < 8; j++) {
                if (a[i][j]) {
                    s[0] = (s[0] + k[j]) & 0xffffffff;
                } else {
                    s[1] = (s[1] + k[j]) & 0xffffffff;
                }
            }
            //     C) K[i+1] = encryptCFB (S[i], K[i], K[i])
            let iv = new Uint8Array(s.buffer);
            k = new Int32Array(this.encryptCFB.call(this, k, k, iv));
            //     D) i = i + 1
        }
        // 5) Let K(UKM) be K[8].
        return k;
    }

    /**
     * Algorithm name GOST 28147-CPKW<br><br>
     *
     * This algorithm encrypts GOST 28147-89 CEK with a GOST 28147 KEK.
     * It can be used with any KEK (e.g., produced by VKO GOST R 34.10-94 or
     * VKO GOST R 34.10-2001) because a unique UKM is used to diversify the KEK.
     * Ref. rfc4357 6.3  CryptoPro Key Wrap
     *
     */
    wrapKeyCP(kek, cek) {
        let n = this.blockSize;
        let k = this.keySize;
        let len = k + (n >> 1);
        // 1) For a unique symmetric KEK or a KEK produced by VKO GOST R
        // 34.10-94, generate 8 octets at random.  Call the result UKM.  For
        // a KEK, produced by VKO GOST R 34.10-2001, use the UKM that was
        // used for key derivation.
        if (!this.ukm) {
            throw new Error('UKM must be defined');
        }
        let ukm = new Uint8Array(this.ukm);
        // 2) Diversify KEK, using the CryptoPro KEK Diversification Algorithm,
        // described in Section 6.5.  Call the result KEK(UKM).
        let dek = this.diversifyKEK.call(this, kek, ukm);
        // 3) Compute a 4-byte checksum value, GOST 28147IMIT (UKM, KEK(UKM),
        // CEK).  Call the result CEK_MAC.
        let mac = this.signMAC(dek, cek, ukm);
        // 4) Encrypt CEK in ECB mode using KEK(UKM).  Call the ciphertext
        // CEK_ENC.
        let enc = this.encryptECB.call(this, dek, cek);
        // 5) The wrapped content-encryption key is (UKM | CEK_ENC | CEK_MAC).
        let r = new Uint8Array(len);
        r.set(new Uint8Array(enc), 0);
        r.set(new Uint8Array(mac), k);
        return r.buffer;
    }

    /**
     * Algorithm name GOST 28147-CPKW<br><br>
     *
     * This algorithm encrypts GOST 28147-89 CEK with a GOST 28147 KEK.
     * Ref. rfc4357 6.4 CryptoPro Key Unwrap
     */
    unwrapKeyCP(kek, data) {
        let n = this.blockSize;
        let k = this.keySize;
        let len = k + (n >> 1);
        // 1) If the wrapped content-encryption key is not 44 octets, then error.
        let d = GostCoding.buffer(data);
        if (d.byteLength !== len) {
            throw new Error('Wrapping key size must be ' + len + ' bytes');
        }
        // 2) Decompose the wrapped content-encryption key into UKM, CEK_ENC,
        // and CEK_MAC.  UKM is the most significant (first) 8 octets.
        // CEK_ENC is next 32 octets, and CEK_MAC is the least significant
        // (last) 4 octets.
        if (!this.ukm) {
            throw new Error('UKM must be defined');
        }
        let ukm = new Uint8Array(this.ukm);
        let enc = new Uint8Array(d, 0, k);
        let mac = new Uint8Array(d, k, n >> 1);
        // 3) Diversify KEK using the CryptoPro KEK Diversification Algorithm,
        // described in section 6.5.  Call the result KEK(UKM).
        let dek = this.diversifyKEK.call(this, kek, ukm);
        // 4) Decrypt CEK_ENC in ECB mode using KEK(UKM).  Call the output CEK.
        let cek = this.decryptECB.call(this, dek, enc);
        // 5) Compute a 4-byte checksum value, GOST 28147IMIT (UKM, KEK(UKM),
        // CEK), compare the result with CEK_MAC.  If they are not equal,
        // then it is an error.
        let check = this.verifyMAC.call(this, dek, mac, cek, ukm);
        if (!check) {
            throw new Error('Error verify MAC of wrapping key');
        }
        return cek;
    }

    /**
     * SignalCom master key packing algorithm
     *
     * kek stored in 3 files - kek.opq, mk.db3, masks.db3
     * kek.opq - always 36 bytes length = 32 bytes encrypted kek + 4 bytes mac of decrypted kek
     * mk.db3 - 6 bytes header (1 byte magic code 0x22 + 1 byte count of masks + 4 bytes mac of
     * xor summarizing masks value) + attached masks
     * masks.db3 - detached masks.
     * Total length  of attached + detached masks = 32 bits * count of masks
     * Default value of count 8 = (7 attached + 1 detached). But really no reason for such
     * separation - all masks xor summarizing - order is not matter.
     * Content of file rand.opq can used as ukm. Don't forget change file content after using.
     *
     * For usb-token files has names:
     * a001 - mk.db3, b001 - masks.db3, c001 - kek.opq, d001 - rand.opq
     * For windows registry
     * 00000001 - mk.db3, 00000002 - masks.db3, 00000003 - key.opq, 00000004 - rand.opq,
     * 00000006 - keys\00000001.key, 0000000A - certificate
     *
     * @memberOf GostCipher
     * @method packKey
     * @param   unpacked - clear main key 32 bytes
     * @param   ukm - random vector for packing - 32 bytes * (count of masks - 1)
     * @returns packed master key - concatination of mk.db3 + masks.db3
     */
    packKeySC(unpacked, ukm) {
        let m = this.blockSize >> 1;
        let k = this.keySize;
        let mcount = 8;
        let key = new Uint8Array(GostCoding.buffer(unpacked));
        if (key.byteLength !== k) {
            throw new Error('Wrong cleartext size ' + key.byteLength + ' bytes');
        }
        // Check or generate UKM
        ukm = ukm || this.ukm;
        if (ukm) {
            ukm = new Uint8Array(GostCoding.buffer(ukm));
            if (ukm.byteLength > 0 && ukm.byteLength % k === 0) {
                mcount = ukm.byteLength / k + 1;
            } else {
                throw new Error('Wrong rand size ' + ukm.byteLength + ' bytes');
            }
        } else {
            this.randomSeed(ukm = new Uint8Array((mcount - 1) * k));
        }
        // Output array
        let d = new Uint8Array(mcount * k + m + 2);
        let b = d.buffer;
        // Calculate MAC
        let zero32 = new Uint8Array(k);
        let mac = this.signMAC(key, zero32, undefined);
        d[0] = 0x22; // Magic code
        d[1] = mcount; // Count of masks
        d.set(new Uint8Array(mac), 2);
        d.set(ukm, k + m + 2);
        for (let i = 1; i < mcount; i++) {
            let mask = new Uint8Array(b, 2 + m + k * i);
            for (let j = 0; j < k; j++) {
                key[j] ^= mask[j];
            }
        }
        d.set(key, m + 2);
        return d.buffer;
    }

    /**
     * Algorithm name GOST 28147-SCKW<br><br>
     *
     * SignalCom master key unpacking algorithm
     *
     * @memberOf GostCipher
     * @method unpackKey
     * @param  packed - concatination of mk.db3 + masks.db3
     * @returns } unpacked master key
     */
    unpackKeySC(packed) {
        let m = this.blockSize >> 1;
        let k = this.keySize;
        let b = GostCoding.buffer(packed);
        // Unpack master key
        let magic = new Uint8Array(b, 0, 1)[0];
        if (magic !== 0x22) {
            throw new Error('Invalid magic number');
        }
        let mcount = new Uint8Array(b, 1, 1)[0];
        let mac = new Uint8Array(b, 2, m); // MAC for summarized mask
        // Compute packKey xor summing for all masks
        let key = new Uint8Array(k);
        for (let i = 0; i < mcount; i++) {
            let mask = new Uint8Array(b, 2 + m + k * i, k);
            for (let j = 0; j < k; j++) {
                key[j] ^= mask[j];
            }
        }
        // Test MAC for packKey with default sBox on zero 32 bytes array
        let test = this.verifyMACSC.call(this, key, mac, () => new Uint8Array(k));
        if (!test) {
            throw new Error('Invalid main key MAC');
        }
        return key.buffer;
    }

    verifyMACSC(key, mac, dataCallable) {
        // Use default and then try to use different sBoxes
        let names = ['default', 'E-A', 'E-B', 'E-C', 'E-D', 'E-SC'];
        for (let i = 0, n = names.length; i < n; i++) {
            if (typeof this.sBoxes[names[i]] !== 'undefined') {
                this.sBox = this.sBoxes[names[i]];
            }
            if (this.verifyMAC.call(this, key, mac, dataCallable.call(this))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Algorithm name GOST 28147-SCKW<br><br>
     *
     * SignalCom Key Wrapping algorithm
     */
    wrapKeySC(kek, cek) {
        let m = this.blockSize >> 1;
        let n = this.keySize;
        let k = GostCoding.buffer(kek);
        let c = GostCoding.buffer(cek);
        if (k.byteLength !== n) {
            k = this.unpackKeySC.call(this, k);
        }
        let enc = this.encryptECB.call(this, k, c);
        let mac = this.signMAC(k, c, undefined);
        let d = new Uint8Array(m + n);
        d.set(new Uint8Array(enc), 0);
        d.set(new Uint8Array(mac), n);
        return d.buffer;
    }

    /**
     * Algorithm name GOST 28147-SCKW<br><br>
     *
     * SignalCom Key UnWrapping algorithm
     */
    unwrapKeySC(kek, cek) {
        let m = this.blockSize >> 1;
        let n = new Uint8Array(cek).length - m;
        let k = GostCoding.buffer(kek);
        let c = GostCoding.buffer(cek);
        if (k.byteLength !== this.keySize) {
            k = this.unpackKeySC.call(this, k);
        }
        let enc = new Uint8Array(c, 0, n); // Encrypted kek
        let mac = new Uint8Array(c, n, m); // MAC for clear kek

        let d;
        let test = this.verifyMACSC.call(this, k, mac, function() {
            d = this.decryptECB.call(this, k, enc);
            return d;
        });
        if (!test) {
            throw new Error('Invalid key MAC');
        }

        return d;
    }

    /**
     * Algorithm name GOST 28147-SCKW<br><br>
     *
     * SignalCom master key generation for wrapping
     *
     */
    generateWrappingKeySC() {
        return this.packKeySC.call(this, this.generateKey.call(this)); // FIXME WTF
    }

    maskKey(mask, key, inverse, keySize) {
        let k = keySize / 4;
        let m32 = new Int32Array(GostCoding.buffer(mask));
        let k32 = new Int32Array(GostCoding.buffer(key));
        let r32 = new Int32Array(k);
        if (inverse) {
            for (let i = 0; i < k; i++) {
                r32[i] = (k32[i] + m32[i]) & 0xffffffff;
            }
        } else {
            for (let i = 0; i < k; i++) {
                r32[i] = (k32[i] - m32[i]) & 0xffffffff;
            }
        }
        return r32.buffer;
    }

    /**
     * Algorithm name GOST 28147-MASK<br><br>
     *
     * This algorithm wrap key mask
     *
     * @memberOf GostCipher
     * @method wrapKey
     */
    wrapKeyMask(mask, key) {
        return this.maskKey(mask, key, this.procreator === 'VN', this.keySize);
    }


    /**
     * Algorithm name GOST 28147-CPKW<br><br>
     *
     * This algorithm unwrap key mask
     *
     * @memberOf GostCipher
     * @method unwrapKey
     */
    unwrapKeyMask(mask, key) {
        return this.maskKey(mask, key, this.procreator !== 'VN', this.keySize);
    }

    /**
     * Algorithm name GOST 28147-CPKM<br><br>
     *
     * Key meshing in according to rfc4357 2.3.2. CryptoPro Key Meshing
     *
     * @memberOf GostCipher
     * @method keyMeshing
     */
    keyMeshingCP(k: Uint8Array, s: Uint8Array, i: number, key: Int32Array, e: boolean) {
        if ((i + 1) * this.blockSize % 1024 === 0) { // every 1024 octets
            // K[i+1] = decryptECB (K[i], C);
            k = this.decryptECB.call(this, k, this.C);
            // IV0[i+1] = encryptECB (K[i+1],IVn[i])
            s.set(new Uint8Array(this.encryptECB.call(this, k, s)));
            // restore key schedule
            key.set(this.keySchedule(k, e));
        }
        return k;
    }

    /**
     *  Null Key Meshing in according to rfc4357 2.3.1
     *
     * @memberOf GostCipher
     * @method keyMeshing
     */

    noKeyMeshing(k) {
        return k;
    }

    /**
     * Algorithm name GOST 28147-NoPadding<br><br>
     *
     * No padding.
     *
     * @memberOf GostCipher
     * @method padding
     */
    noPad(d: Uint8Array): Uint8Array {
        return new Uint8Array(d);
    }

    /**
     * Algorithm name GOST 28147-PKCS5Padding<br><br>
     *
     *  PKCS#5 padding: 8-x remaining bytes are filled with the value of
     *  8-x.  If there’s no incomplete block, one extra block filled with
     *  value 8 is added
     *
     * @memberOf GostCipher
     * @method padding
     */
    pkcs5Pad(d: Uint8Array): Uint8Array {
        let n = d.byteLength;
        let nb = this.blockSize;
        let q = nb - n % nb;
        let m = Math.ceil((n + 1) / nb) * nb;
        let r = new Uint8Array(m);
        r.set(d);
        for (let i = n; i < m; i++) {
            r[i] = q;
        }
        return r;
    }

    pkcs5Unpad(d: Uint8Array): Uint8Array {
        let m = d.byteLength;
        let nb = this.blockSize;
        let q = d[m - 1];
        let n = m - q;
        if (q > nb) {
            throw Error('Invalid padding');
        }
        let r = new Uint8Array(n);
        if (n > 0) {
            r.set(new Uint8Array(d.buffer, 0, n));
        }
        return r;
    }

    /**
     * Algorithm name GOST 28147-ZeroPadding<br><br>
     *
     * Zero padding: 8-x remaining bytes are filled with zero
     *
     * @memberOf GostCipher
     * @method padding
     */
    zeroPad(d: Uint8Array): Uint8Array {
        let n = d.byteLength;
        let nb = this.blockSize;
        let m = Math.ceil(n / nb) * nb;
        let r = new Uint8Array(m);
        r.set(d);
        for (let i = n; i < m; i++) {
            r[i] = 0;
        }
        return r;
    }

    /**
     * Algorithm name GOST 28147-BitPadding<br><br>
     *
     * Bit padding: P* = P || 1 || 000...0 If there’s no incomplete block,
     * one extra block filled with 1 || 000...0
     *
     */
    bitPad(d: Uint8Array): Uint8Array {
        let n = d.byteLength;
        let nb = this.blockSize;
        let m = Math.ceil((n + 1) / nb) * nb;
        let r = new Uint8Array(m);
        r.set(d);
        r[n] = 1;
        for (let i = n + 1; i < m; i++) {
            r[i] = 0;
        }
        return r;
    }

    bitUnpad(d: Uint8Array): Uint8Array {
        let m = d.byteLength;
        let n = m;
        while (n > 1 && d[n - 1] === 0) {
            n--;
        }
        if (d[n - 1] !== 1) {
            throw Error('Invalid padding');
        }
        n--;
        let r = new Uint8Array(n);
        if (n > 0) {
            r.set(new Uint8Array(d.buffer, 0, n));
        }
        return r;
    }

    /**
     * Algorithm name GOST 28147-RandomPadding<br><br>
     *
     * Random padding: 8-x remaining bytes of the last block are set to
     * random.
     *
     */
    randomPad(d: Uint8Array): Uint8Array {
        let n = d.byteLength;
        let nb = this.blockSize;
        let q = nb - n % nb;
        let m = Math.ceil(n / nb) * nb;
        let r = new Uint8Array(m);
        let e = new Uint8Array(r.buffer, n, q);
        r.set(d);
        this.randomSeed(e);
        return r;
    }

}




