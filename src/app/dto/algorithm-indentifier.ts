export class AlgorithmIndentifier {
    name: string;
    version: number;
    block: string;
    keyWrapping: string;
    shiftBits: number;
    padding: string;
    mode: string;
    keyMeshing;
    procreator: string;
    sBox: any; // : string | ArrayBuffer;
    iv: any; // string | ArrayBuffer ;
    macLength: number;
    length: number;
    ukm: any; //  ArrayBuffer | string;


    /*from digest*/
    salt: ArrayBuffer;
    iterations: number;
    diversifier: number;
    context: ArrayBuffer;
    label: ArrayBuffer;
    keySize: number;
}
