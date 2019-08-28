import {GostSign} from './gost-sign';
import {Chars, GostCoding, Hex} from '../gost-coding/gost-coding';
import {AlgorithmDto} from '../../dto/algorithm-dto';

describe('GostSign', () => {
    it('should create an instance', () => {
        expect(new GostSign(undefined)).toBeTruthy();
    });


    it('GOST R 34.10-94 TEST 1', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.10';
        algorithm.version = 1994;
        algorithm.namedParam = 'S-TEST';
        algorithm.ukm = '90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A';

        const result = perform(algorithm,
            '3534454132454236443134453437313943363345374143423445413631454230',
            '3036314538303830343630454235324435324234314132373832433138443046',
            'ee1902a40692d273edc1b5adc55f91128e35f9d165fa9901caf00d27018ba6df324519c11a6e272526589cd6e6a2eddaafe1c3081259be9fcee667a2701f4352',
            '3F0DD5D4400D47C08E4CE505FF7434B6DBF729592E37C74856DAB85115A609553E5F895E276D81D2D52C0763270A458157B784C57ABDBD807BC44FD43A32AC06');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('GOST R 34.10-94 TEST 2', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.10';
        algorithm.namedCurve = 'S-256-TEST';
       // algorithm.namedParam = 'S-TEST';
        algorithm.ukm = '77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3';

        const result = perform(algorithm,
            '2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5',
            '7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28',
            '26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B',
            '01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C4041AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493');
        expect(result.includes('PASSED')).toBeTruthy();
    });



    it('GOST R 34.10-94 TEST 3', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.10';
        algorithm.namedCurve = 'T-512-TEST';
        // algorithm.namedParam = 'S-TEST';
        algorithm.ukm = '359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1';

        const result = perform(algorithm,
            '3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C5917184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C',
            'BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4',
            '37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61EA199441D943FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD5A515856D13314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1',
            '1081B394696FFE8E6585E7A9362D26B6325F56778AADBC081C0BFBE933D52FF5823CE288E8C4F362526080DF7F70CE406A6EEB1F56919CB92A9853BDE73E5B4A2F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD35492558486B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36');
        expect(result.includes('PASSED')).toBeTruthy();
    });



    it('GOST R 34.10-94 TEST 4', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.10';
        algorithm.namedCurve = 'S-256-TEST';
        // algorithm.namedParam = 'S-TEST';
        // algorithm.ukm = '359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1';

        const result = perform(algorithm,
            '2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5',
            '7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28',
            '26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B', undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });



    it('GOST R 34.10-94 TEST 5', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.10';
        algorithm.namedCurve = 'S-256-TEST';
        // algorithm.namedParam = 'S-TEST';
        // algorithm.ukm = '359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1';

        const result = perform(algorithm,
            '2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5',
            undefined,
            undefined, undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });




    it('GOST R 34.10-94 TEST 6', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.10';
        algorithm.namedCurve = 'S-256-TEST';
        algorithm.hash = {
            name: 'GOST R 34.11',
            version: 1994
        };
        // algorithm.namedParam = 'S-TEST';
        // algorithm.ukm = '359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1';

        const result = perform(algorithm,
            Chars.decode('Suppose the original message has length = 50 bytes', undefined),
            undefined,
            undefined, undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });



    it('GOST R 34.10-94 TEST 7', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.10';
        algorithm.namedCurve = 'T-512-TEST';
        algorithm.hash = {
            version: undefined,
            name: 'GOST R 34.11'
        };
        // algorithm.namedParam = 'S-TEST';
        // algorithm.ukm = '359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1';

        const result = perform(algorithm,
            Chars.decode('Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы', undefined),
            undefined,
            undefined, undefined);
        expect(result.includes('PASSED')).toBeTruthy();
    });




    it('GOST R 34.10-94 TEST 8', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.10';
        algorithm.namedCurve = 'S-256-TEST';
        algorithm.mode = 'DH';
        // algorithm.namedParam = 'S-TEST';
        algorithm.ukm = '77105C9B20BCD312';

        const result = performDerive(algorithm);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('GOST R 34.10-94 TEST 9', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.10';
        algorithm.namedCurve = 'X-256-A';
        algorithm.mode = 'DH';
        // algorithm.namedParam = 'S-TEST';
        algorithm.ukm = '77105C9B20BCD312';
        algorithm.hash = {
            version: undefined,
            name: 'GOST R 34.11'
        };
        const result = performDerive(algorithm);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('GOST R 34.10-94 TEST 10', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.10';
        algorithm.namedCurve = 'X-256-A';
        algorithm.mode = 'DH';
        // algorithm.namedParam = 'S-TEST';
        algorithm.ukm = '77105C9B20BCD312';
        algorithm.hash = {
            name: 'GOST R 34.11',
            version: 1994
        };
        const result = performDerive(algorithm);
        expect(result.includes('PASSED')).toBeTruthy();
    });
});


function perform(algorithm, message, privateKey, publicKey, output) {

    if (algorithm.ukm) {
        (algorithm.ukm = Hex.decode(algorithm.ukm, true));
    } else {
        output = false;
    }

    const gostSign = new GostSign(algorithm);
    let result = 'Test ' + ' ' + (gostSign.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    const data = typeof message === 'string' ? Hex.decode(message, true) : message;

    if (!privateKey) {
        const keyPair = gostSign.generateKey();
        privateKey = keyPair.privateKey;
        publicKey = keyPair.publicKey;
        output = false;
    } else {
        privateKey = Hex.decode(privateKey, true);
        publicKey = Hex.decode(publicKey, true);
    }

    try {
        let start;
        let signed;
        let verified;
        start = new Date().getTime();
        const out = Hex.encode(gostSign.sign(privateKey, data), true);
        let test = (output && out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase() !== output.toLowerCase());
        if (!test) {
            signed = new Date().getTime();
            test = (!gostSign.verify(publicKey, Hex.decode(out, true), data));
            verified = new Date().getTime();
            if (!test) {
                result += 'PASSED Sign ' + (signed - start) / 1000 + ' sec, Verify ' + (verified - signed) / 1000 + ' sec';
            } else {
                result += 'FAILED - Verify return (false)';
            }
        } else {
            result += 'FAILED - Sign expected ' + output.toLowerCase() + ' got ' + out.toLowerCase();
        }
    } catch (e) {
        console.error(e);
        result += 'FAILED - Throw error: ' + e.message;
    }

    console.log(result);
    return result;
}



function performDerive(algorithm: AlgorithmDto) {
    const ukm = algorithm.ukm;
    delete algorithm.ukm;
    let cipher = new GostSign(algorithm);
    let result = 'Test ' + ' ' + (cipher.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    const keyPair1 = cipher.generateKey();
    const keyPair2 = cipher.generateKey();
    const privateKey1 = keyPair1.privateKey;
    const publicKey1 = keyPair1.publicKey;
    const privateKey2 = keyPair2.privateKey;
    const publicKey2 = keyPair2.publicKey;
    // const gostCoding = new GostCoding();
    try {
        if (ukm) {
            (algorithm.ukm = Hex.decode(ukm, undefined));
        }

        const start = new Date().getTime();
        algorithm.public = publicKey2;
        cipher = new GostSign(algorithm);
        const kek1 = Hex.encode(cipher.deriveKey(privateKey1), undefined);
        const finish = new Date().getTime();

        algorithm.public = publicKey1;
        cipher = new GostSign(algorithm);
        const kek2 = Hex.encode(cipher.deriveKey(privateKey2), undefined);

        const test = (kek1 !== kek2);
        if (!test) {
            result += 'PASSED DeriveKey ' + (finish - start) / 1000 + ' sec';
        } else {
            result += 'PASSED DeriveKey - one side got ' + kek1 + ' but other side got ' + kek2;
        }
    } catch (e) {
        result += 'FAILED - Throw error: ' + e.message;
    }
    console.log(result);
    return result;
}
