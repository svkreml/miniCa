export class AlgorithmDto {
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



    /*from sign*/
    namedParam: string;
    namedCurve: string;
    hash: HashDto | string;
    public: any;
    param: any;
    modulusLength: number;
    curve: any;
    id: any;
}
export class HashDto {
    name: string = undefined;
    version: number = undefined;
}
