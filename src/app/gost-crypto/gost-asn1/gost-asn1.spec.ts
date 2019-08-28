import { GostAsn1 } from './gost-asn1';
import {AlgorithmDto} from '../../dto/algorithm-dto';

describe('GostAsn1', () => {
  it('should create an instance', () => {
    expect(new GostAsn1(new AlgorithmDto())).toBeTruthy();
  });
});
