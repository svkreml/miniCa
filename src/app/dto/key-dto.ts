import {AlgorithmDto} from './algorithm-dto';

export class Key {
    algorithm: AlgorithmDto;
    type: string;
    usages: any[];
    buffer: ArrayBuffer;

}
