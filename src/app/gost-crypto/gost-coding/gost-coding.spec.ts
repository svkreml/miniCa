import {Chars, Hex} from './gost-coding';

describe('GostCoding', () => {



    it('hex encode-decode test', () => {

        let input = '11121314151617181920aabbcceeff';
        let decoded = Hex.decode(input);
        let encoded = Hex.encode(decoded);

        console.log('expected ' + input + ' , got ' + encoded + ', ' + (encoded === input ? 'PASSED' : 'FAILED') );
        expect(encoded === input).toBeTruthy();
    });
    it('chars encode-decode test', () => {

        let input = 'abcdef12345!@#$%^&*()_+?><MNBVCZXAQWSDERFGTHYJUKKILO:P"{_}}}}}\\\\';
        let decoded = Chars.decode(input, undefined);
        let encoded = Chars.encode(decoded, undefined);

        console.log('expected ' + input + ' , got ' + encoded + ', ' + (encoded === input ? 'PASSED' : 'FAILED') );
        expect(encoded === input).toBeTruthy();
    });
});
