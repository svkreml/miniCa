import {Chars, Hex} from './gost-coding';

describe('GostCoding', () => {


    it('hex encode-decode test', () => {

        const input = '11121314151617181920aabbcceeff';
        const decoded = Hex.decode(input, undefined);
        const encoded = Hex.encode(decoded, undefined);

        console.log('expected ' + input + ' , got ' + encoded + ', ' + (encoded === input ? 'PASSED' : 'FAILED'));
        expect(encoded === input).toBeTruthy();
    });
    it('chars encode-decode test', () => {

        const input = 'abcdef12345!@#$%^&*()_+?><MNBVCZXAQWSDERFGTHYJUKKILO:P"{_}}}}}\\\\';
        const decoded = Chars.decode(input, undefined);
        const encoded = Chars.encode(decoded, undefined);

        console.log('expected ' + input + ' , got ' + encoded + ', ' + (encoded === input ? 'PASSED' : 'FAILED'));
        expect(encoded === input).toBeTruthy();
    });
});
