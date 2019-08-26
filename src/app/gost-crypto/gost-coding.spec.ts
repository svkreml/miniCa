import { GostCoding } from './gost-coding';
import {GostCipher} from './gost-cipher';
import {GostRandom} from './gost-random';
import {AlgorithmIndentifier} from '../dto/algorithm-indentifier';

describe('GostCoding', () => {
  it('should create an instance', () => {
    expect(new GostCoding(new GostCipher(new GostRandom(), new AlgorithmIndentifier()))).toBeTruthy();
  });
});
