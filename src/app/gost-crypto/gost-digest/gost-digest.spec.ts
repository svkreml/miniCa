import {AlgorithmDto} from '../../dto/algorithm-dto';
import {Chars, Hex} from '../gost-coding/gost-coding';
import {GostDigest} from './gost-digest';

describe('GostDigest', () => {


    it('GOST R 34.11 1994 1', () => {
        const algorithm: AlgorithmDto = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.version = 1994;
        const result = digest(algorithm, Chars.decode('', undefined),
            '981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('GOST R 34.11 1994 2', () => {
        const algorithm: AlgorithmDto = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.version = 1994;
        const result = digest(algorithm, Chars.decode('This is message, length=32 bytes', undefined),
            '2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('GOST R 34.11 1994 3', () => {
        const algorithm: AlgorithmDto = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.version = 1994;
        const result = digest(algorithm, Chars.decode('Suppose the original message has length = 50 bytes', undefined),
            'c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('GOST R 34.11 1994 4', () => {
        const algorithm: AlgorithmDto = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.version = 1994;
        const result = digest(algorithm, Chars.decode('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', undefined),
            '73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('GOST R 34.11 1994 5', () => {
        const algorithm: AlgorithmDto = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.version = 1994;
        const result = digest(algorithm, Chars.decode(new Array(1000001).join('a'), undefined),
            '8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    const algorithm2 = new AlgorithmDto();
    algorithm2.name = 'GOST R 34.11';
    algorithm2.version = 1994;
    algorithm2.sBox = 'D-TEST';


    it('GOST R 34.11 1994 D-TEST 1', () => {
        const algorithm2 = new AlgorithmDto();
        algorithm2.name = 'GOST R 34.11';
        algorithm2.version = 1994;
        algorithm2.sBox = 'D-TEST';

        const result = digest(algorithm2, Chars.decode('', undefined),
            'ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('GOST R 34.11 1994 D-TEST 2', () => {
        const algorithm2 = new AlgorithmDto();
        algorithm2.name = 'GOST R 34.11';
        algorithm2.version = 1994;
        algorithm2.sBox = 'D-TEST';

        const result = digest(algorithm2, Chars.decode('This is message, length=32 bytes', undefined),
            'b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('GOST R 34.11 1994 D-TEST 3', () => {
        const algorithm2 = new AlgorithmDto();
        algorithm2.name = 'GOST R 34.11';
        algorithm2.version = 1994;
        algorithm2.sBox = 'D-TEST';

        const result = digest(algorithm2, Chars.decode('Suppose the original message has length = 50 bytes', undefined),
            '471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('GOST R 34.11 1994 D-TEST 4', () => {
        const algorithm2 = new AlgorithmDto();
        algorithm2.name = 'GOST R 34.11';
        algorithm2.version = 1994;
        algorithm2.sBox = 'D-TEST';

        const result = digest(algorithm2, Chars.decode('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', undefined),
            '95c1af627c356496d80274330b2cff6a10c67b5f597087202f94d06d2338cf8e');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('PBKDF2 1', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.mode = 'PBKDF2';
        algorithm.version = 1994;
        // algorithm.sBox = 'D-TEST';
        algorithm.salt = Chars.decode('salt', undefined);
        algorithm.iterations = 1;
        const result = deriveKey(algorithm,
            Chars.decode('password', undefined),
            '7314e7c04fb2e662c543674253f68bd0b73445d07f241bed872882da21662d58');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('PBKDF2 2', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.mode = 'PBKDF2';
        algorithm.version = 1994;
        // algorithm.sBox = 'D-TEST';
        algorithm.salt = Chars.decode('salt', undefined);
        algorithm.iterations = 2;
        const result = deriveKey(algorithm,
            Chars.decode('password', undefined),
            '990dfa2bd965639ba48b07b792775df79f2db34fef25f274378872fed7ed1bb3');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('PBKDF2 3', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.mode = 'PBKDF2';
        algorithm.version = 1994;
        // algorithm.sBox = 'D-TEST';
        algorithm.salt = Chars.decode('salt', undefined);
        algorithm.iterations = 1000;
        const result = deriveKey(algorithm,
            Chars.decode('password', undefined),
            '2b6e0a5cc2103274dd3353fb86e4983c6451f8025a51cd9ddfd33361c6cb572b');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('PBKDF2 4096 1', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.mode = 'PBKDF2';
        algorithm.version = 1994;
        // algorithm.sBox = 'D-TEST';
        algorithm.salt = Chars.decode('salt', undefined);
        algorithm.iterations = 4096;
        const result = deriveKey(algorithm,
            Chars.decode('password', undefined),
            '1f1829a94bdff5be10d0aeb36af498e7a97467f3b31116a5a7c1afff9deadafe');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('PBKDF2 4096 2', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.mode = 'PBKDF2';
        algorithm.version = 1994;
        // algorithm.sBox = 'D-TEST';
        algorithm.salt = Chars.decode('saltSALTsaltSALTsaltSALTsaltSALTsalt', undefined);
        algorithm.iterations = 4096;
        const result = deriveBits(algorithm,
            Chars.decode('passwordPASSWORDpassword', undefined),
            '788358c69cb2dbe251a7bb17d5f4241f265a792a35becde8d56f326b49c85047b7638acb4764b1fd',
            320);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('PBKDF2 4096 3', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.mode = 'PBKDF2';
        algorithm.version = 1994;
        // algorithm.sBox = 'D-TEST';
        algorithm.salt = Chars.decode('sa\0lt', undefined);
        algorithm.iterations = 4096;
        const result = deriveBits(algorithm,
            Chars.decode('pass\0word', undefined),
            '43e06c5590b08c0225242373127edf9c8e9c3291',
            160);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('GOST R 34.11-2012 1', () => {
        const algorithm = new AlgorithmDto();
        const result = digest(algorithm,
            Chars.decode('012345678901234567890123456789012345678901234567890123456789012', undefined),
            '9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('GOST R 34.11-2012 2', () => {
        const algorithm = new AlgorithmDto();
        const result = digest(algorithm,
            Chars.decode('Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы', undefined),
            '9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('GOST R 34.11-2012 3', () => {
        const algorithm = new AlgorithmDto();
        const result = digest(algorithm,
            new Uint8Array(0),
            '3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('GOST R 34.11-2012 4', () => {
        const algorithm = new AlgorithmDto();
        const result = digest(algorithm,
            new Uint8Array([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            'df1fda9ce83191390537358031db2ecaa6aa54cd0eda241dc107105e13636b95');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('GOST R 34.11-2012 5', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.version = 2012;
        algorithm.mode = 'KDF';
        algorithm.context = Hex.decode('af21434145656378');
        algorithm.label = Hex.decode('26bdb878');
        const result = deriveKey(algorithm,
            Hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
            'a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('GOST R 34.11-2012 6', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.version = 2012;
        algorithm.mode = 'KDF';
        algorithm.context = Hex.decode('af21434145656378');
        algorithm.label = Hex.decode('26bdb878');
        const result = deriveBits(algorithm,
            Hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
            '22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9',
            512);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('HMAC/PBKDF2 1', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        // algorithm.version = 2012;
        algorithm.mode = 'HMAC';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        const result = sign(algorithm,
            Hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
            'a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9',
            Hex.decode('0126bdb87800af214341456563780100')
        );
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('HMAC/PBKDF2 2', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.length = 512;
        // algorithm.version = 2012;
        algorithm.mode = 'HMAC';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        const result = sign(algorithm,
            Hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
            'a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6',
            Hex.decode('0126bdb87800af214341456563780100')
        );
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('HMAC/PBKDF2 3', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        // algorithm.length = 512;
        // algorithm.version = 2012;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('salt', undefined);
        algorithm.iterations = 1000;


        const result = deriveKey(algorithm,
            Chars.decode('password', undefined),
            'c5f66589be62e183038e5dee22ea3d7a32afb314abd9970dc8f66858d1a924f4'
        );
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('HMAC/PBKDF2 4', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.length = 512;
        // algorithm.version = 2012;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('salt', undefined);
        algorithm.procreator = 'VN';
        algorithm.iterations = 1;


        const result = deriveBits(algorithm,
            Chars.decode('password', undefined),
            'bcd19a1c423a63e72e47ef0f56566c726745d96ac1a1c127b2edadb45fb45b307aca15999e91f640f4818f68af716e30fd543c52026bbb295d100eb471339f46',
            512);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('HMAC/PBKDF2 5', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.length = 512;
        // algorithm.version = 2012;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('salt', undefined);
        algorithm.procreator = 'VN';
        algorithm.iterations = 2;


        const result = deriveBits(algorithm,
            Chars.decode('password', undefined),
            '088fec3b0f1ffaf0615eb267de92907fd4e0bb89d2f5ef9d4111a80e3cbf231af07ba3ce96065395f8f1a7505f9781f97e99a26b8314907dbf3510bc3ca2000c',
            512);
        expect(result.includes('PASSED')).toBeTruthy();
    });



    it('GOST R 34.11-12-512 1', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.length = 512;
        // algorithm.version = 2012;
       // algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
       // algorithm.salt = Chars.decode('salt', undefined);
       // algorithm.procreator = 'VN';
       // algorithm.iterations = 2;


        const result = digest(algorithm,
            Chars.decode('012345678901234567890123456789012345678901234567890123456789012', undefined),
            '1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('GOST R 34.11-12-512 2', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.length = 512;
        // algorithm.version = 2012;
        // algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        // algorithm.salt = Chars.decode('salt', undefined);
        // algorithm.procreator = 'VN';
        // algorithm.iterations = 2;


        const result = digest(algorithm,
            Chars.decode('Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы', undefined),
            '1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('GOST R 34.11-12-512 3', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.length = 512;
        // algorithm.version = 2012;
        // algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        // algorithm.salt = Chars.decode('salt', undefined);
        // algorithm.procreator = 'VN';
        // algorithm.iterations = 2;


        const result = digest(algorithm,
            new Uint8Array(0),
            '8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('GOST R 34.11-12-512 4', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.length = 512;
        // algorithm.version = 2012;
        // algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        // algorithm.salt = Chars.decode('salt', undefined);
        // algorithm.procreator = 'VN';
        // algorithm.iterations = 2;


        const result = digest(algorithm,
            new Uint8Array([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            'b0fd29ac1b0df441769ff3fdb8dc564df67721d6ac06fb28ceffb7bbaa7948c6c014ac999235b58cb26fb60fb112a145d7b4ade9ae566bf2611402c552d20db7');
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('PBKDF2 4096 2012 1', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        // algorithm.length = 512;
        // algorithm.version = 2012;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('salt', undefined);
        // algorithm.procreator = 'VN';
        algorithm.iterations = 4096;

        const result = deriveKey(algorithm,
            Chars.decode('password', undefined),
            'd744dc35ddfe10c7679af205ceb6492fb3680f861db598ee8110b30e3a0f3cb4');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('PBKDF2 4096 2012 2', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        // algorithm.length = 512;
        // algorithm.version = 2012;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('saltSALTsaltSALTsaltSALTsaltSALTsalt', undefined);
        // algorithm.procreator = 'VN';
        algorithm.iterations = 4096;

        const result = deriveBits(algorithm,
            Chars.decode('passwordPASSWORDpassword', undefined),
            '8452d34400e6404864f12206a2ac3f932fe7fe55026b1dd8f21a645cf340cbf0cca377e603024e82',
            320);
        expect(result.includes('PASSED')).toBeTruthy();
    });



    it('PBKDF2 4096 2012 3', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        // algorithm.length = 512;
        // algorithm.version = 2012;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('sa\0lt', undefined);
        // algorithm.procreator = 'VN';
        algorithm.iterations = 4096;

        const result = deriveBits(algorithm,
            Chars.decode('pass\0word', undefined),
            '5023f9b3cc41e5aa491ea3e9eb65b6c01ffbeb63',
            160);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('PBKDF2 4096 2012 4', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.length = 512;
        // algorithm.version = 2012;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('salt', undefined);
        algorithm.procreator = 'VN';
        algorithm.iterations = 4096;

        const result = deriveBits(algorithm,
            Chars.decode('password', undefined),
            '596f63971eae970a4eac9c18bff42ec52b936c1ccac6d17caa308afe12d4ff31943180ce02e42956524e991392c4bddeb7077edc1d2abf52eaf72b9e32a8c605',
            512);
        expect(result.includes('PASSED')).toBeTruthy();
    });




    it('PBKDF2 4096 2012 5', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.length = 512;
        // algorithm.version = 2012;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('saltSALTsaltSALTsaltSALTsaltSALTsalt', undefined);
        algorithm.procreator = 'VN';
        algorithm.iterations = 4096;

        const result = deriveBits(algorithm,
            Chars.decode('passwordPASSWORDpassword', undefined),
            'e457ee6126f07c09be004ba512adc90c611c2b3fa11141c21196dae5a48a50d83ccf163233f014fb6ade7169' +
            '5bf37159e9062443b75dac911fa7a181d24c4ed2a910499d72aba93284c78dbc1acba2789bd8ef50b5052f33ec6e2491f4f74eda05723864',
            800);
        expect(result.includes('PASSED')).toBeTruthy();
    });




    it('PBKDF2 4096 2012 6', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'GOST R 34.11';
        algorithm.length = 512;
        // algorithm.version = 2012;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('sa\0lt', undefined);
        algorithm.procreator = 'VN';
        algorithm.iterations = 4096;

        const result = deriveBits(algorithm,
            Chars.decode('pass\0word', undefined),
            'eed92e8d76e18d6a632f2da65c9b2859af555c3335ea30095989dea14d9d093114668e' +
            '329deb034cc1565c3d731de0b5ca11acbdf85ab9eaab15295df05b9805',
            512);
        expect(result.includes('PASSED')).toBeTruthy();
    });




    it('SHA1 1', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'SHA';
       // algorithm.length = 512;
        algorithm.version = 1;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
      //  algorithm.salt = Chars.decode('sa\0lt', undefined);
      //  algorithm.procreator = 'VN';
       // algorithm.iterations = 4096;

        const result = digest(algorithm,
            Chars.decode('abc', undefined),
            'a9993e364706816aba3e25717850c26c9cd0d89d');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('SHA1 2', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'SHA';
        // algorithm.length = 512;
        algorithm.version = 1;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        //  algorithm.salt = Chars.decode('sa\0lt', undefined);
        //  algorithm.procreator = 'VN';
        // algorithm.iterations = 4096;

        const result = digest(algorithm,
            Chars.decode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', undefined),
            '84983e441c3bd26ebaae4aa1f95129e5e54670f1');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('SHA1 3', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'SHA';
        // algorithm.length = 512;
        algorithm.version = 1;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        //  algorithm.salt = Chars.decode('sa\0lt', undefined);
        //  algorithm.procreator = 'VN';
        // algorithm.iterations = 4096;

        const result = digest(algorithm,
            Chars.decode(new Array(11).join('0123456701234567012345670123456701234567012345670123456701234567'), undefined),
            'dea356a2cddd90c7a7ecedc5ebb563934f460452');
        expect(result.includes('PASSED')).toBeTruthy();
    });




    it('PBKDF2 4096 SHA1 1', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'SHA';
        // algorithm.length = 512;
        algorithm.version = 1;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('salt', undefined);
        //  algorithm.procreator = 'VN';
        algorithm.iterations = 4096;

        const result = deriveKey(algorithm,
            Chars.decode('password', undefined),
            '4b007901b765489abead49d926f721d065a429c1');
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('PBKDF2 4096 SHA1 2', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'SHA';
        // algorithm.length = 512;
        algorithm.version = 1;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('saltSALTsaltSALTsaltSALTsaltSALTsalt', undefined);
        //  algorithm.procreator = 'VN';
        algorithm.iterations = 4096;

        const result = deriveBits(algorithm,
            Chars.decode('passwordPASSWORDpassword', undefined),
            '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038',
            200);
        expect(result.includes('PASSED')).toBeTruthy();
    });

    it('PBKDF2 4096 SHA1 3', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'SHA';
        // algorithm.length = 512;
        algorithm.version = 1;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('sa\0lt', undefined);
        //  algorithm.procreator = 'VN';
        algorithm.iterations = 4096;

        const result = deriveBits(algorithm,
            Chars.decode('pass\0word', undefined),
            '56fa6aa75548099dcc37d7f03425e0c3',
            128);
        expect(result.includes('PASSED')).toBeTruthy();
    });


    it('PBKDF2 4096 SHA1 4', () => {
        const algorithm = new AlgorithmDto();
        algorithm.name = 'SHA';
        // algorithm.length = 512;
        algorithm.version = 1;
        algorithm.mode = 'PBKDF2';
        // algorithm.context = Hex.decode('af21434145656378');
        // algorithm.label = Hex.decode('26bdb878');
        algorithm.salt = Chars.decode('sa\0lt', undefined);
        //  algorithm.procreator = 'VN';
        algorithm.iterations = 4096;

        const result = digest(algorithm,
            Chars.decode(new Array(1000001).join('a'), undefined),
            '34aa973cd4c4daa4f61eeb2bdbad27316534016f');
        expect(result.includes('PASSED')).toBeTruthy();
    });


});


function digest(algorithm: AlgorithmDto, input: ArrayBuffer, output) {
    const gostDigest = new GostDigest(algorithm);
    let start;
    let finish;
    let out;
    let result;
    let test;


    start = new Date().getTime();
    result = 'Test ' + ' ' + (gostDigest.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    try {

        out = Hex.encode(gostDigest.digest(input));
        finish = new Date().getTime();
        out = out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase();
        test = (out !== output);
        if (test) {
            result += 'FAILED: Expected ' + output + ' got ' + out;
        } else {
            result += 'PASSED ' + (finish - start) / 1000 + ' sec';
        }
    } catch (e) {
        result += 'FAILED - Throw error: ' + e.message;
    }

    console.log(result);
    return result;
}

function deriveKey(algorithm: AlgorithmDto, input: ArrayBuffer, output: string) {

    let start;
    let finish;
    let out;
    let result;
    let test;
    const gostDigest = new GostDigest(algorithm);

    start = new Date().getTime();
    result = 'Test ' + ' ' + (gostDigest.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    try {
        out = Hex.encode(gostDigest.deriveKey(input));
        finish = new Date().getTime();
        out = out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase();
        test = (out !== output);
        if (test) {
            result += 'FAILED: Expected ' + output + ' got ' + out;
        } else {
            result += 'PASSED ' + (finish - start) / 1000 + ' sec';
        }
    } catch (e) {
        result += 'FAILED - Throw error: ' + e.message;
    }

    console.log(result);
    return result;
}


function deriveBits(algorithm: AlgorithmDto, input: ArrayBuffer, output: string, param: number) {

    let start;
    let finish;
    let out;
    let result;
    let test;
    const gostDigest = new GostDigest(algorithm);

    start = new Date().getTime();
    result = 'Test ' + ' ' + (gostDigest.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    try {
        out = Hex.encode(gostDigest.deriveBits(input, param));
        finish = new Date().getTime();
        out = out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase();
        test = (out !== output);
        if (test) {
            result += 'FAILED: Expected ' + Hex.encode(input) + ' got ' + out;
        } else {
            result += 'PASSED ' + (finish - start) / 1000 + ' sec';
        }
    } catch (e) {
        result += 'FAILED - Throw error: ' + e.message;
    }

    console.log(result);
    return result;
}


function sign(algorithm: AlgorithmDto, input: ArrayBuffer, output, data) {
    const gostDigest = new GostDigest(algorithm);
    let start;
    let finish;
    let out;
    let result;
    let test;


    start = new Date().getTime();
    result = 'Test ' + ' ' + (gostDigest.name + ' ' + new Array(61).join('.')).substring(0, 60) + ' ';
    try {

        out = Hex.encode(gostDigest.sign(input, data));
        finish = new Date().getTime();
        out = out.replace(/[^\-A-Fa-f0-9]/g, '').toLowerCase();
        test = (out !== output);
        if (test) {
            result += 'FAILED: Expected ' + 'sign' + ' got ' + out;
        } else {
            result += 'PASSED ' + (finish - start) / 1000 + ' sec';
        }
    } catch (e) {
        result += 'FAILED - Throw error: ' + e.message;
    }

    console.log(result);
    return result;
}
