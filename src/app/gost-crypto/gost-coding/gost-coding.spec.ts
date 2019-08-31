import {Base64, Chars, Hex} from './gost-coding';
import {GostViewer} from '../gost-viewer/gost-viewer';
import {GostKeyContainerName} from '../gost-asn1/gost-asn1';
import {GostViewerTestData} from '../gost-viewer/GostViewerTestData';

describe('GostCoding', () => {


    it('hex encode-decode undefined', () => {

        const input = '11121314151617181920aabbcceeff';
        const decoded = Hex.decode(input, undefined);
        const encoded = Hex.encode(decoded, undefined);

        console.log('expected ' + input + ' , got ' + encoded + ', ' + (encoded === input ? 'PASSED' : 'FAILED'));
        expect(encoded === input).toBeTruthy();
    });

    it('hex encode-decode false', () => {

        const input = '11121314151617181920aabbcceeff';
        const decoded = Hex.decode(input, false);
        const encoded = Hex.encode(decoded, false);

        console.log('expected ' + input + ' , got ' + encoded + ', ' + (encoded === input ? 'PASSED' : 'FAILED'));
        expect(encoded === input).toBeTruthy();
    });


    it('hex encode-decode true', () => {

        const input = '11121314151617181920aabbcceeff';
        const decoded = Hex.decode(input, true);
        const encoded = Hex.encode(decoded, true);

        console.log('expected ' + input + ' , got ' + encoded + ', ' + (encoded === input ? 'PASSED' : 'FAILED'));
        expect(encoded === input).toBeTruthy();
    });


    it('chars encode-decode undefined', () => {

        const input = 'abcdef12345!@#$%^&*()_+?><MNBVCZXAQWSDERFGTHYJUKKILO:P"{_}}}}}\\\\';
        const decoded = Chars.decode(input, undefined);
        const encoded = Chars.encode(decoded, undefined);

        console.log('expected ' + input + ' , got ' + encoded + ', ' + (encoded === input ? 'PASSED' : 'FAILED'));
        expect(encoded === input).toBeTruthy();
    });


    it('chars encode-decode win1251', () => {

        const input = 'abcdef12345!@#$%^&*()_+?><MNBVCZXAQWSDERFGTHYJUKKILO:P"{_}}}}}\\\\';
        const decoded = Chars.decode(input, 'win1251');
        const encoded = Chars.encode(decoded, 'win1251');

        console.log('expected ' + input + ' , got ' + encoded + ', ' + (encoded === input ? 'PASSED' : 'FAILED'));
        expect(encoded === input).toBeTruthy();
    });

    it('chars encode-decode utf8', () => {

        const input = 'abcdef12345!@#$%^&*()_+?><MNBVCZXAQWSDERFGTHYJUKKILO:P"{_}}}}}\\\\';
        const decoded = Chars.decode(input, 'utf8');
        const encoded = Chars.encode(decoded, 'utf8');

        console.log('expected ' + input + ' , got ' + encoded + ', ' + (encoded === input ? 'PASSED' : 'FAILED'));
        expect(encoded === input).toBeTruthy();
    });



    it('base64Test ', () => {




        let decoded = Base64.decode(GostViewerTestData.cryptoProName);
        let encoded = Base64.encode(decoded);

        console.log(GostViewerTestData.cryptoProName);
        console.log(encoded);


        expect(encoded === GostViewerTestData.cryptoProName).toBeTruthy();
    });
});
