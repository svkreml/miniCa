import {GostSign} from './gost-sign';
import {Hex} from '../gost-coding/gost-coding';
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
        expect(result).toBeTruthy();
    });


});


function perform(algorithm, message, privateKey, publicKey, output) {

    if (algorithm.ukm) {
        (algorithm.ukm = Hex.decode(algorithm.ukm, true));
    } else {
        output = false;
    }

    const cipher = new GostSign(algorithm);
    let result = 'Test ' + ' ' + (cipher.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    const data = typeof message === 'string' ? Hex.decode(message, true) : message;

    if (!privateKey) {
        const keyPair = cipher.generateKey();
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
        const out = Hex.encode(cipher.sign(privateKey, data), true);
        let test = (output && out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase() !== output.toLowerCase());
        if (!test) {
            signed = new Date().getTime();
            test = (!cipher.verify(publicKey, Hex.decode(out, true), data));
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
        result += 'FAILED - Throw error: ' + e.message;
    }

    console.log(result);
    return result;
}
