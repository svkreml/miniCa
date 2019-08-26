export class AlgorithmIndentifier {
    name: string;
    version: number;
    block: string;
    keyWrapping: string;
    shiftBits: number;
    padding: string;
    mode: string;
    keyMeshing;
    procreator;
    sBox;
    iv;
    macLength;
    length: number;
    ukm;


    /*from digest*/
    salt: any;
    iterations: number;
    diversifier: number;
    context: any;
    label: any;
    keySize: number;
}
