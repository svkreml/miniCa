import {GostRandom} from '../gost-random/gost-random';
import {AlgorithmDto} from '../../dto/algorithm-dto';
import {GostDigest} from '../gost-digest/gost-digest';

export class GostSign {

    DB = 28;
    ONE = this.nbv(1);
    private ECGostParams = {
        'S-256-TEST': {
            a: 7,
            b: '0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E',
            p: '0x8000000000000000000000000000000000000000000000000000000000000431',
            q: '0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3',
            x: 2,
            y: '0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8'
        },
        'S-256-A': {
            a: '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94',
            b: 166,
            p: '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97',
            q: '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893',
            x: 1,
            y: '0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14'
        },
        'S-256-B': {
            a: '0x8000000000000000000000000000000000000000000000000000000000000C96',
            b: '0x3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B',
            p: '0x8000000000000000000000000000000000000000000000000000000000000C99',
            q: '0x800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F',
            x: 1,
            y: '0x3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC'
        },
        'S-256-C': {
            a: '0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598',
            b: 32858,
            p: '0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B',
            q: '0x9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9',
            x: 0,
            y: '0x41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67'
        },
        'P-256': {
            p: '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
            a: '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
            b: '0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
            x: '0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296',
            y: '0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5',
            q: '0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'
        },
        'T-512-TEST': {
            a: 7,
            b: '0x1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC',
            p: '0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373',
            q: '0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF',
            x: '0x24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A',
            y: '0x2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E'
        },
        'T-512-A': {
            p: '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7',
            a: '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4',
            b: '0xE8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760',
            q: '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275',
            x: 3,
            y: '0x7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4'
        },
        'T-512-B': {
            p: '0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F',
            a: '0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C',
            b: '0x687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116',
            q: '0x800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD',
            x: 2,
            y: '0x1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD'
        }
    };
    private GostParams = {
        'S-TEST': {
            modulusLength: 512, // bit length of p (512 or 1024 bits)
            p: '0xEE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3',
            q: '0x98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D',
            a: '0x9e96031500c8774a869582d4afde2127afad2538b4b6270a6f7c8837b50d50f206755984a49e509304d648be2ab5aab18ebe2cd46ac3d8495b142aa6ce23e21c'
        },
        'S-A': {
            modulusLength: 1024,
            p: '0xB4E25EFB018E3C8B87505E2A67553C5EDC56C2914B7E4F89D23F03F03377E70A2903489DD60E78418D3D851EDB5317C4871E40B04228C3B7902963C4B7D85D52B9AA88F2AFDBEB28DA8869D6DF846A1D98924E925561BD69300B9DDD05D247B5922D967CBB02671881C57D10E5EF72D3E6DAD4223DC82AA1F7D0294651A480DF',
            q: '0x972432A437178B30BD96195B773789AB2FFF15594B176DD175B63256EE5AF2CF',
            a: '0x8FD36731237654BBE41F5F1F8453E71CA414FFC22C25D915309E5D2E62A2A26C7111F3FC79568DAFA028042FE1A52A0489805C0DE9A1A469C844C7CABBEE625C3078888C1D85EEA883F1AD5BC4E6776E8E1A0750912DF64F79956499F1E182475B0B60E2632ADCD8CF94E9C54FD1F3B109D81F00BF2AB8CB862ADF7D40B9369A'
        },
        'S-B': {
            modulusLength: 1024,
            p: '0xC6971FC57524B30C9018C5E621DE15499736854F56A6F8AEE65A7A404632B1BCF0349FFCAFCB0A103177971FC1612ADCDB8C8CC938C70225C8FD12AFF01B1D064E0AD6FDE6AB9159166CB9F2FC171D92F0CC7B6A6B2CD7FA342ACBE2C9315A42D576B1ECCE77A963157F3D0BD96A8EB0B0F3502AD238101B05116334F1E5B7AB',
            q: '0xB09D634C10899CD7D4C3A7657403E05810B07C61A688BAB2C37F475E308B0607',
            a: '0x3D26B467D94A3FFC9D71BF8DB8934084137264F3C2E9EB16DCA214B8BC7C872485336744934FD2EF5943F9ED0B745B90AA3EC8D70CDC91682478B664A2E1F8FB56CEF2972FEE7EDB084AF746419B854FAD02CC3E3646FF2E1A18DD4BEB3C44F7F2745588029649674546CC9187C207FB8F2CECE8E2293F68395C4704AF04BAB5'
        },
        'S-C': {
            modulusLength: 1024,
            p: '0x9D88E6D7FE3313BD2E745C7CDD2AB9EE4AF3C8899E847DE74A33783EA68BC30588BA1F738C6AAF8AB350531F1854C3837CC3C860FFD7E2E106C3F63B3D8A4C034CE73942A6C3D585B599CF695ED7A3C4A93B2B947B7157BB1A1C043AB41EC8566C6145E938A611906DE0D32E562494569D7E999A0DDA5C879BDD91FE124DF1E9',
            q: '0xFADD197ABD19A1B4653EECF7ECA4D6A22B1F7F893B641F901641FBB555354FAF',
            a: '0x7447ED7156310599070B12609947A5C8C8A8625CF1CF252B407B331F93D639DDD1BA392656DECA992DD035354329A1E95A6E32D6F47882D960B8F10ACAFF796D13CD9611F853DAB6D2623483E46788708493937A1A29442598AEC2E0742022563440FE9C18740ECE6765AC05FAF024A64B026E7E408840819E962E7E5F401AE3'
        },
        'S-D': {
            modulusLength: 1024,
            p: '0x80F102D32B0FD167D069C27A307ADAD2C466091904DBAA55D5B8CC7026F2F7A1919B890CB652C40E054E1E9306735B43D7B279EDDF9102001CD9E1A831FE8A163EED89AB07CF2ABE8242AC9DEDDDBF98D62CDDD1EA4F5F15D3A42A6677BDD293B24260C0F27C0F1D15948614D567B66FA902BAA11A69AE3BCEADBB83E399C9B5',
            q: '0xF0F544C418AAC234F683F033511B65C21651A6078BDA2D69BB9F732867502149',
            a: '0x6BCC0B4FADB3889C1E06ADD23CC09B8AB6ECDEDF73F04632595EE4250005D6AF5F5ADE44CB1E26E6263C672347CFA26F9E9393681E6B759733784CDE5DBD9A14A39369DFD99FA85CC0D10241C4010343F34A91393A706CF12677CBFA1F578D6B6CFBE8A1242CFCC94B3B653A476E145E3862C18CC3FED8257CFEF74CDB205BF1'
        },
        'X-A': {
            modulusLength: 1024,
            p: '0xCA3B3F2EEE9FD46317D49595A9E7518E6C63D8F4EB4D22D10D28AF0B8839F079F8289E603B03530784B9BB5A1E76859E4850C670C7B71C0DF84CA3E0D6C177FE9F78A9D8433230A883CD82A2B2B5C7A3306980278570CDB79BF01074A69C9623348824B0C53791D53C6A78CAB69E1CFB28368611A397F50F541E16DB348DBE5F',
            q: '0xCAE4D85F80C147704B0CA48E85FB00A9057AA4ACC44668E17F1996D7152690D9',
            a: '0xBE27D652F2F1E339DA734211B85B06AE4DE236AA8FBEEB3F1ADCC52CD43853777E834A6A518138678A8ADBD3A55C70A7EAB1BA7A0719548677AAF4E609FFB47F6B9D7E45B0D06D83D7ADC53310ABD85783E7317F7EC73268B6A9C08D260B85D8485696CA39C17B17F044D1E050489036ABD381C5E6BF82BA352A1AFF136601AF'
        },
        'X-B': {
            modulusLength: 1024,
            p: '0x9286DBDA91ECCFC3060AA5598318E2A639F5BA90A4CA656157B2673FB191CD0589EE05F4CEF1BD13508408271458C30851CE7A4EF534742BFB11F4743C8F787B11193BA304C0E6BCA25701BF88AF1CB9B8FD4711D89F88E32B37D95316541BF1E5DBB4989B3DF13659B88C0F97A3C1087B9F2D5317D557DCD4AFC6D0A754E279',
            q: '0xC966E9B3B8B7CDD82FF0F83AF87036C38F42238EC50A876CD390E43D67B6013F',
            a: '0x7E9C3096676F51E3B2F9884CF0AC2156779496F410E049CED7E53D8B7B5B366B1A6008E5196605A55E89C3190DABF80B9F1163C979FCD18328DAE5E9048811B370107BB7715F82091BB9DE0E33EE2FED6255474F8769FCE5EAFAEEF1CB5A32E0D5C6C2F0FC0B3447072947F5B4C387666993A333FC06568E534AD56D2338D729'
        },
        'X-C': {
            modulusLength: 1024,
            p: '0xB194036ACE14139D36D64295AE6C50FC4B7D65D8B340711366CA93F383653908EE637BE428051D86612670AD7B402C09B820FA77D9DA29C8111A8496DA6C261A53ED252E4D8A69A20376E6ADDB3BDCD331749A491A184B8FDA6D84C31CF05F9119B5ED35246EA4562D85928BA1136A8D0E5A7E5C764BA8902029A1336C631A1D',
            q: '0x96120477DF0F3896628E6F4A88D83C93204C210FF262BCCB7DAE450355125259',
            a: '0x3F1817052BAA7598FE3E4F4FC5C5F616E122CFF9EBD89EF81DC7CE8BF56CC64B43586C80F1C4F56DD5718FDD76300BE336784259CA25AADE5A483F64C02A20CF4A10F9C189C433DEFE31D263E6C9764660A731ECCAECB74C8279303731E8CF69205BC73E5A70BDF93E5BB681DAB4EEB9C733CAAB2F673C475E0ECA921D29782E'
        }
    };
    private DM = (1 << this.DB) - 1;
    private DV = 1 << this.DB;
    private FV = Math.pow(2, 52);
    private F1 = 52 - this.DB;
    private F2 = 2 * this.DB - 52;
    private ZERO = this.nbv(0);
    private THREE = this.nbv(3);


    /*
    * algorithm
    * */
    private procreator: string;
    name: string;
    private ukm: any;
    private curve: Curve;
    // tslint:disable-next-line:variable-name
    private peer_Q: any;
    private P: { curve: any; x: any; y: any; z: any };
    private q: any;
    private p: any;
    private a: any;
    // tslint:disable-next-line:variable-name
    private peer_y: any;
    private namedCurve: string;
    private namedParam: string;
    private modulusLength: number | number;
    private keyLength: any;
    private dostDigest: GostDigest;
    private version: number;
   // private sign: any;
   // private verify: any;
  //  private generateKey: any;
  //  private deriveBits: any;
  //  private deriveKey: any;
  //  private wrapKey: any;
  //  private unwrapKey: any;


    constructor(algorithm: AlgorithmDto) {
        this.ECGostParams['X-256-A'] = this.ECGostParams['S-256-C'];
        this.ECGostParams['T-256-TEST'] = this.ECGostParams['S-256-TEST'];
        this.ECGostParams['T-256-A'] = this.ECGostParams['S-256-A'];
        this.ECGostParams['T-256-B'] = this.ECGostParams['S-256-B'];
        this.ECGostParams['T-256-C'] = this.ECGostParams['S-256-C'];


        if (!algorithm) {
            algorithm = new AlgorithmDto();
        }
        this.name = (algorithm.name || 'GOST R 34.10') + '-' +
            ((algorithm.version || 2012) % 100) + '-' + (algorithm.length || 256) +
            (((algorithm.mode || 'SIGN') !== 'SIGN') ? '-' + algorithm.mode : '') +
            (typeof algorithm.namedParam === 'string' ? '/' + algorithm.namedParam : '') +
            (typeof algorithm.namedCurve === 'string' ? '/' + algorithm.namedCurve : '') +
            (typeof algorithm.sBox === 'string' ? '/' + algorithm.sBox : '');

        this.version = algorithm.version || 2012;

        // Functions
        switch (algorithm.mode || 'SIGN') {
            case 'SIGN':
               // this.sign = sign;
               // this.verify = verify;
               // this.generateKey = generateKey;
                break;
            case 'DH':
               // this.deriveBits = deriveBits;
               // this.deriveKey = deriveKey;
               // this.generateKey = generateKey;
               // break;
            case 'MASK':
              //  this.wrapKey = wrapKey;
              //  this.unwrapKey = unwrapKey;
              //  this.generateKey = generateMaskKey;
                break;
        }

        // Define parameters
        if (this.version === 1994) {
            // Named or parameters algorithm
            let param = algorithm.param;
            if (!param) {
                param = this.GostParams[this.namedParam = (algorithm.namedParam || 'S-A').toUpperCase()];
            }
            this.modulusLength = algorithm.modulusLength || param.modulusLength || 1024;
            this.p = this.htobi(param.p);
            this.q = this.htobi(param.q);
            this.a = this.htobi(param.a);
            // Public key for derive
            if (algorithm.public) {
                this.peer_y = this.atobi(algorithm.public);
            }
        } else {
            // Named or parameters algorithm
            let param = algorithm.curve;
            if (!param) {
                param = this.ECGostParams[this.namedCurve = (algorithm.namedCurve || 'S-256-A').toUpperCase()];
            }
            const curve = this.curve = this.newCurve(this.htobi(param.p), this.htobi(param.a), this.htobi(param.b));
            this.P = this.newEC(curve,
                this.newFE(curve, this.htobi(param.x)),
                this.newFE(curve, this.htobi(param.y)), undefined);
            this.q = this.htobi(param.q);
            // Public key for derive
            if (algorithm.public) {
                const k2 = this.to2(algorithm.public);
                this.peer_Q = this.newEC(this.curve, // This corresponds to the binary representation of (<y>256||<x>256)
                    this.newFE(this.curve, k2[0]), // first 32 octets contain the little-endian representation of x
                    this.newFE(this.curve, k2[1]), undefined); // and second 32 octets contain the little-endian representation of y.
            }
        }

        // Check bit length
        let hashLen;
        let keyLen;
        if (this.curve) {
            keyLen = algorithm.length || this.bitLength(this.q);
            if (keyLen > 508 && keyLen <= 512) {
                keyLen = 512;
            } else if (keyLen > 254 && keyLen <= 256) {
                keyLen = 256;
            } else {
                throw new Error('Support keys only 256 or 512 bits length');
            }
            hashLen = keyLen;
        } else {
            keyLen = algorithm.modulusLength || this.bitLength(this.p);
            if (keyLen > 1016 && keyLen <= 1024) {
                keyLen = 1024;
            } else if (keyLen > 508 && keyLen <= 512) {
                keyLen = 512;
            } else {
                throw new Error('Support keys only 512 or 1024 bits length');
            }
            hashLen = 256;
        }
        this.bitLength = hashLen;
        this.keyLength = keyLen;

        // Algorithm proceator for result conversion
        this.procreator = algorithm.procreator;

        // Hash private definition
        let hash = algorithm.hash;
        if (hash) {
            if (typeof hash === 'string' || hash instanceof String) {
                hash = {name: hash};
            }
            if (algorithm.version === 1994 || algorithm.version === 2001) {
                hash.version = 1994;
                hash.length = 256;
                hash.sBox = algorithm.sBox || hash.sBox;
            } else {
                hash.version = 2012;
                hash.length = hashLen;
            }
            hash.procreator = hash.procreator || algorithm.procreator;


            this.dostDigest = new GostDigest(hash);

        }

        // Pregenerated seed for key exchange algorithms
        if (algorithm.ukm) { // Now don't check size
            this.ukm = algorithm.ukm;
        }

    }


    invDig(a) {
        if (a.t < 1) {
            return 0;
        }
        const x = a[0];
        if ((x & 1) === 0) {
            return 0;
        }
        let y = x & 3;
        y = (y * (2 - (x & 0xf) * y)) & 0xf;
        y = (y * (2 - (x & 0xff) * y)) & 0xff;
        y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;
        y = (y * (2 - x * y % this.DV)) % this.DV;
        return (y > 0) ? this.DV - y : -y;
    }

    nbi(words): any { // FIXME бред
        const r: any = new Array(Math.ceil(words));
        r.s = 0;
        r.t = 0;
        return r;
    }

    copyTo(x, r) {
        for (let i = x.t - 1; i >= 0; --i) {
            r[i] = x[i];
        }
        r.t = x.t;
        r.s = x.s;
        return r;
    }

    clamp(x) {
        const c = x.s & this.DM;
        while (x.t > 0 && x[x.t - 1] === c) {
            --x.t;
        }
        return x;
    }

    subTo(x, a, r) {
        let i = 0;
        let c = 0;
        const m = Math.min(a.t, x.t);
        while (i < m) {
            c += x[i] - a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        if (a.t < x.t) {
            c -= a.s;
            while (i < x.t) {
                c += x[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += x.s;
        } else {
            c += x.s;
            while (i < a.t) {
                c -= a[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c -= a.s;
        }
        r.s = (c < 0) ? -1 : 0;
        if (c < -1) {
            r[i++] = this.DV + c;
        } else if (c > 0) {
            r[i++] = c;
        }
        r.t = i;
        return this.clamp(r);
    }

    compare(x, a) {
        let r = x.s - a.s;
        if (r !== 0) {
            return r;
        }
        let i = x.t;
        r = i - a.t;
        if (r !== 0) {
            return (x.s < 0) ? -r : r;
        }
        while (--i >= 0) {
            if ((r = x[i] - a[i]) !== 0) {
                return r;
            }
        }
        return 0;
    }

    dshlTo(x, n, r) {
        let i;
        for (i = x.t - 1; i >= 0; --i) {
            r[i + n] = x[i];
        }
        for (i = n - 1; i >= 0; --i) {
            r[i] = 0;
        }
        r.t = x.t + n;
        r.s = x.s;
        return r;
    }

    dshrTo(x, n, r) {
        for (let i = n; i < x.t; ++i) {
            r[i - n] = x[i];
        }
        r.t = Math.max(x.t - n, 0);
        r.s = x.s;
        return r;
    }

    mulTo(b, a, r) {
        const x = this.abs(b);
        const y = this.abs(a);
        let i = x.t;
        r.t = i + y.t;
        while (--i >= 0) {
            r[i] = 0;
        }
        for (i = 0; i < y.t; ++i) {
            r[i + x.t] = this.am(x, 0, y[i], r, i, 0, x.t);
        }
        r.s = 0;
        if (b.s !== a.s) {
            this.subTo(this.ZERO, r, r);
        }
        return this.clamp(r);
    }

    sqrTo(a, r) {
        const x = this.abs(a);
        let i = r.t = 2 * x.t;
        while (--i >= 0) {
            r[i] = 0;
        }
        for (i = 0; i < x.t - 1; ++i) {
            const c = this.am(x, i, x[i], r, 2 * i, 0, 1);
            if ((r[i + x.t] += this.am(x, i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
                r[i + x.t] -= x.DV;
                r[i + x.t + 1] = 1;
            }
        }
        if (r.t > 0) {
            r[r.t - 1] += this.am(x, i, x[i], r, 2 * i, 0, 1);
        }
        r.s = 0;
        return this.clamp(r);
    }

    modTo(b, a, r) {
        this.divRemTo(this.abs(b), a, null, r);
        if (b.s < 0 && this.compare(r, this.ZERO) > 0) {
            this.subTo(a, r, r);
        }
        return r;
    }

    mod(b, a) {
        return this.modTo(b, a, this.nbi(a.t));
    }

    div(b, a) {
        return this.divRemTo(b, a, this.nbi(Math.max(b.t - a.t, 1)), null);
    }

    nothing(x) {
        return x;
    }

    dAddOffset(x, n, w) {
        if (n === 0) {
            return;
        }
        while (x.t <= w) {
            x[x.t++] = 0;
        }
        x[w] += n;
        while (x[w] >= this.DV) {
            x[w] -= this.DV;
            if (++w >= x.t) {
                x[x.t++] = 0;
            }
            ++x[w];
        }
    }

    mulLowerTo(x, a, n, r) {
        let i = Math.min(x.t + a.t, n);
        r.s = 0; // assumes a,x >= 0
        r.t = i;
        while (i > 0) {
            r[--i] = 0;
        }
        let j;
        for (j = r.t - x.t; i < j; ++i) {
            r[i + x.t] = this.am(x, 0, a[i], r, i, 0, x.t);
        }
        for (j = Math.min(a.t, n); i < j; ++i) {
            this.am(x, 0, a[i], r, i, 0, n - i);
        }
        return this.clamp(r);
    }

    mulUpperTo(x, a, n, r) {
        --n;
        let i = r.t = x.t + a.t - n;
        r.s = 0; // assumes a,x >= 0
        while (--i >= 0) {
            r[i] = 0;
        }
        for (i = Math.max(n - x.t, 0); i < a.t; ++i) {
            r[x.t + i - n] = this.am(x, n - i, a[i], r, 0, 0, x.t + i - n);
        }
        this.clamp(r);
        return this.dshrTo(r, 1, r);
    }

    private absTo(x, r) {
        return (x.s < 0) ? this.negTo(r, undefined) : this.copyTo(r, undefined);
    }

    private setInt(x, i) {
        x.t = 1;
        x.s = (i < 0) ? -1 : 0;
        if (i > 0) {
            x[0] = i;
        } else if (i < -1) {
            x[0] = i + this.DV;
        } else {
            x.t = 0;
        }
        return x;
    }

    private am(y, i, x, w, j, c, n): number {
        const xl = x & 0x3fff;
        const xh = x >> 14;
        while (--n >= 0) {
            let l = y[i] & 0x3fff;
            const h = y[i++] >> 14;
            const m = xh * l + h * xl;
            l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
            c = (l >> 28) + (m >> 14) + xh * h;
            w[j++] = l & 0xfffffff;
        }
        return c;
    }

    private copy(x) {
        return this.copyTo(x, this.nbi(x.t));
    }

    private nbv(i) {
        const r = this.nbi(1);
        this.setInt(r, i);
        return r;
    }

    private sub(x, y) {
        return this.subTo(x, y, this.nbi(x.t));
    }

    private addTo(x, a, r) {
        let i = 0;
        let c = 0;
        const m = Math.min(a.t, x.t);
        while (i < m) {
            c += x[i] + a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        if (a.t < x.t) {
            c += a.s;
            while (i < x.t) {
                c += x[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += x.s;
        } else {
            c += x.s;
            while (i < a.t) {
                c += a[i];
                r[i++] = c & this.DM;
                c = c >> this.DB;
            }
            c += a.s;
        }
        r.s = (c < 0) ? -1 : 0;
        if (c > 0) {
            r[i++] = c;
        } else if (c < -1) {
            r[i++] = this.DV + c;
        }
        r.t = i;
        return this.clamp(r);
    }

    private add(x, y) {
        return this.addTo(x, y, this.nbi(x.t));
    }

    private negTo(x, r) {
        return this.subTo(this.ZERO, x, r);
    }

    private neg(x) {
        return this.negTo(x, this.nbi(x.t));
    }

    private abs(x) {
        return (x.s < 0) ? this.neg(x) : x;
    }

    private equals(x, y) {
        return (this.compare(x, y) === 0);
    }

    private min(x, y) {
        return (this.compare(x, y) < 0) ? x : y;
    }

    private max(x, y) {
        return (this.compare(x, y) > 0) ? x : y;
    }

    private nbits(x) {
        let r = 1;
        let t;
        if ((t = x >>> 16) !== 0) {
            x = t;
            r += 16;
        }
        if ((t = x >> 8) !== 0) {
            x = t;
            r += 8;
        }
        if ((t = x >> 4) !== 0) {
            x = t;
            r += 4;
        }
        if ((t = x >> 2) !== 0) {
            x = t;
            r += 2;
        }
        if ((t = x >> 1) !== 0) {
            x = t;
            r += 1;
        }
        return r;
    }

    private shlTo(x, n, r) {
        const bs = n % this.DB;
        const cbs = this.DB - bs;
        const bm = (1 << cbs) - 1;
        const ds = Math.floor(n / this.DB);
        let c = (x.s << bs) & this.DM;
        let i;
        for (i = x.t - 1; i >= 0; --i) {
            r[i + ds + 1] = (x[i] >> cbs) | c;
            c = (x[i] & bm) << bs;
        }
        for (i = ds - 1; i >= 0; --i) {
            r[i] = 0;
        }
        r[ds] = c;
        r.t = x.t + ds + 1;
        r.s = x.s;
        return this.clamp(r);
    }

    private shrTo(x, n, r) {
        r.s = x.s;
        const ds = Math.floor(n / this.DB);
        if (ds >= x.t) {
            r.t = 0;
            return;
        }
        const bs = n % this.DB;
        const cbs = this.DB - bs;
        const bm = (1 << bs) - 1;
        r[0] = x[ds] >> bs;
        for (let i = ds + 1; i < x.t; ++i) {
            r[i - ds - 1] |= (x[i] & bm) << cbs;
            r[i - ds] = x[i] >> bs;
        }
        if (bs > 0) {
            r[x.t - ds - 1] |= (x.s & bm) << cbs;
        }
        r.t = x.t - ds;
        return this.clamp(r);
    }

    private shl(x, n) {
        const r = this.nbi(x.t);
        if (n < 0) {
            this.shrTo(x, -n, r);
        } else {
            this.shlTo(x, n, r);
        }
        return r;
    }

    private shr(x, n) {
        const r = this.nbi(x.t);
        if (n < 0) {
            this.shlTo(x, -n, r);
        } else {
            this.shrTo(x, n, r);
        }
        return r;
    }

    private bitLength(x) {
        if (x.t <= 0) {
            return 0;
        }
        return this.DB * (x.t - 1) + this.nbits(x[x.t - 1] ^ (x.s & this.DM));
    }

    private mul(x, y) {
        return this.mulTo(x, y, this.nbi(x.t + y.t));
    }

    private sqr(a) {
        return this.sqrTo(a, this.nbi(a.t * 2));
    }

    private divRemTo(n, m, q, r) {
        const pm = this.abs(m);
        if (pm.t <= 0) {
            throw new Error('Division by zero');
        }
        const pt = this.abs(n);
        if (pt.t < pm.t) {
            if (q) {
                this.setInt(q, 0);
            }
            if (r) {
                this.copyTo(n, r);
            }
            return q;
        }
        if (!r) {
            r = this.nbi(m.t);
        }
        const y = this.nbi(m.t);
        const ts = n.s;
        const ms = m.s;
        const nsh = this.DB - this.nbits(pm[pm.t - 1]);
        if (nsh > 0) {
            this.shlTo(pm, nsh, y);
            this.shlTo(pt, nsh, r);
        } else {
            this.copyTo(pm, y);
            this.copyTo(pt, r);
        }
        const ys = y.t;
        const y0 = y[ys - 1];
        if (y0 === 0) {
            return q;
        }
        const yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
        const d1 = this.FV / yt;
        const d2 = (1 << this.F1) / yt;
        const e = 1 << this.F2;
        let i = r.t;
        let j = i - ys;
        const t = !q ? this.nbi(Math.max(n.t - m.t, 1)) : q;
        this.dshlTo(y, j, t);
        if (this.compare(r, t) >= 0) {
            r[r.t++] = 1;
            this.subTo(r, t, r);
        }
        this.dshlTo(this.ONE, ys, t);
        this.subTo(t, y, y);
        while (y.t < ys) {
            y[y.t++] = 0;
        }
        while (--j >= 0) {
            let qd = (r[--i] === y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
            if ((r[i] += this.am(y, 0, qd, r, j, 0, ys)) < qd) {
                this.dshlTo(y, j, t);
                this.subTo(r, t, r);
                while (r[i] < --qd) {
                    this.subTo(r, t, r);
                }
            }
        }
        if (q) {
            this.dshrTo(r, ys, q);
            if (ts !== ms) {
                this.subTo(this.ZERO, q, q);
            }
        }
        r.t = ys;
        this.clamp(r);
        if (nsh > 0) {
            this.shrTo(r, nsh, r);
        }
        if (ts < 0) {
            this.subTo(this.ZERO, r, r);
        }
        return q;
    }

    private isEven(x) {

        return ((x.t > 0) ? (x[0] & 1) : x.s) === 0;
    }


    // FIXME Превратить в нормальный класс или вызывать в конструкторе

    private isZero(x) {
        return this.equals(x, this.ZERO);
    }

    private sig(x) {
        if (x.s < 0) {
            return -1;
        } else if (x.t <= 0 || (x.t === 1 && x[0] <= 0)) {
            return 0;
        } else {
            return 1;
        }
    }

    private invMod(x, m) {
        const ac = this.isEven(m);
        if ((this.isEven(x) && ac) || this.sig(m) === 0) {
            return this.ZERO;
        }
        const u = this.copy(m);
        const v = this.copy(x);
        const a = this.nbv(1);
        const b = this.nbv(0);
        const c = this.nbv(0);
        const d = this.nbv(1);
        while (this.sig(u) !== 0) {
            while (this.isEven(u)) {
                this.shrTo(u, 1, u);
                if (ac) {
                    if (!this.isEven(a) || !this.isEven(b)) {
                        this.addTo(a, x, a);
                        this.subTo(b, m, b);
                    }
                    this.shrTo(a, 1, a);
                } else if (!this.isEven(b)) {
                    this.subTo(b, m, b);
                }
                this.shrTo(b, 1, b);
            }
            while (this.isEven(v)) {
                this.shrTo(v, 1, v);
                if (ac) {
                    if (!this.isEven(c) || !this.isEven(d)) {
                        this.addTo(c, x, c);
                        this.subTo(d, m, d);
                    }
                    this.shrTo(c, 1, c);
                } else if (!this.isEven(d)) {
                    this.subTo(d, m, d);
                }
                this.shrTo(d, 1, d);
            }
            if (this.compare(u, v) >= 0) {
                this.subTo(u, v, u);
                if (ac) {
                    this.subTo(a, c, a);
                }
                this.subTo(b, d, b);
            } else {
                this.subTo(v, u, v);
                if (ac) {
                    this.subTo(c, a, c);
                }
                this.subTo(d, b, d);
            }
        }
        if (this.compare(v, this.ONE) !== 0) {
            return this.ZERO;
        }
        if (this.compare(d, m) >= 0) {
             throw new Error('return subtract(d, m);');
            // return subtract(d, m); // FIXME такого нет
        }
        if (this.sig(d) < 0) {
            this.addTo(d, m, d);
        } else {
            return d;
        }
        if (this.sig(d) < 0) {
            return this.add(d, m);
        } else {
            return d;
        }
    }

    private testBit(x, n) {
        const j = Math.floor(n / this.DB);
        if (j >= x.t) {
            return (x.s !== 0);
        }
        return ((x[j] & (1 << (n % this.DB))) !== 0);
    }

    private expMod(x, e, m) {
        let i = this.bitLength(e);
        let k;
        let r = this.nbv(1);
        let z;
        if (i <= 0) {
            return r;
        } else if (i < 18) {
            k = 1;
        } else if (i < 48) {
            k = 3;
        } else if (i < 144) {
            k = 4;
        } else if (i < 768) {
            k = 5;
        } else {
            k = 6;
        }
        if (i < 8) {
            z = new Classic(m, this);
        } else if (this.isEven(m)) {
            z = new Barrett(m, this);
        } else {
            z = new Montgomery(m, this);
        }

        // precomputation
        const g = [];
        let n = 3;
        const k1 = k - 1;
        const km = (1 << k) - 1;
        g[1] = z.convert(x);
        if (k > 1) {
            const g2 = this.nbi(m.t * 2);
            z.sqrTo(g[1], g2);
            while (n <= km) {
                g[n] = this.nbi(m.t * 2);
                z.mulTo(g2, g[n - 2], g[n]);
                n += 2;
            }
        }

        let j = e.t - 1;
        let w;
        let is1 = true;
        let r2 = this.nbi(m.t * 2);
        let t;
        i = this.nbits(e[j]) - 1;
        while (j >= 0) {
            if (i >= k1) {
                w = (e[j] >> (i - k1)) & km;
            } else {
                w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
                if (j > 0) {
                    w |= e[j - 1] >> (this.DB + i - k1);
                }
            }

            n = k;
            while ((w & 1) === 0) {
                w >>= 1;
                --n;
            }
            if ((i -= n) < 0) {
                i += this.DB;
                --j;
            }
            if (is1) {	// ret == 1, don't bother squaring or multiplying it
                this.copyTo(g[w], r);
                is1 = false;
            } else {
                while (n > 1) {
                    z.sqrTo(r, r2);
                    z.sqrTo(r2, r);
                    n -= 2;
                }
                if (n > 0) {
                    z.sqrTo(r, r2);
                } else {
                    t = r;
                    r = r2;
                    r2 = t;
                }
                z.mulTo(r2, g[w], r);
            }
            while (j >= 0 && (e[j] & (1 << i)) === 0) {
                z.sqrTo(r, r2);
                t = r;
                r = r2;
                r2 = t;
                if (--i < 0) {
                    i = this.DB - 1;
                    --j;
                }
            }
        }
        return z.revert(r);
    }


    // ---------------------------------------------------


    // EC Field Elemets
    private newFE(a, x) {
        a.r.reduce(x);
        x.q = a.q;
        x.r = a.r;
        return x;
    }

    private copyFE(a, x) {
        x.q = a.q;
        x.r = a.r;
        return x;
    }

    private negFE(a) {
        return this.copyFE(a, this.sub(a.q, a));
    }

    private addFE(a, b) {
        const r = this.add(a, b);
        if (this.compare(r, a.q) > 0) {
            this.subTo(r, a.q, r);
        }
        return this.copyFE(a, r);
    }

    private subFE(a, b) {
        const r = this.sub(a, b);
        if (r.s < 0) {
            this.addTo(a.q, r, r);
        }
        return this.copyFE(a, r);
    }

    private mulFE(a, b) {
        return this.newFE(a, this.mul(a, b));
    }

    private sqrFE(a) {
        return this.newFE(a, this.sqr(a));
    }

    private shlFE(a, i) {
        return this.newFE(a, this.shl(a, i));
    }

    private invFE(a) {
        return this.copyFE(a, this.invMod(a, a.q));
    }

    // EC Points
    private newEC(curve, x, y, z) {
        return {
            curve,
            x,
            y,
            z: z || this.newFE(curve, this.ONE)
        };
    }

    private getX(point) {
        if (!point.zinv) {
            point.zinv = this.invFE(point.z);
        }
        return this.mulFE(point.x, point.zinv);
    }

    private getY(point) {
        if (!point.zinv) {
            point.zinv = this.invFE(point.z);
        }
        return this.mulFE(point.y, point.zinv);
    }

    private isInfinity(a) {
        if ((!a.x) && (!a.y)) {
            return true;
        }
        return this.isZero(a.z) && !this.isZero(a.y);
    }

    private getInfinity(a) {
        return a.curve.infinity;
    }

    private equalsEC(a, b) {
        if (a === b) {
            return true;
        }
        if (this.isInfinity(a)) {
            return this.isInfinity(b);
        }
        if (this.isInfinity(b)) {
            return this.isInfinity(a);
        }
        let u;
        let v;
        // u = Y2 * Z1 - Y1 * Z2
        u = this.subFE(this.mulFE(b.y, a.z), this.mulFE(a.y, b.z));
        if (!this.isZero(u)) {
            return false;
        }
        // v = X2 * Z1 - X1 * Z2
        v = this.subFE(this.mulFE(b.x, a.z), this.mulFE(a.x, b.z));
        return this.isZero(v);
    }

    private negEC(a) {
        return this.newEC(a.curve, a.x, this.negFE(a.y), a.z);
    }

    private addEC(a, b) {
        if (this.isInfinity(a)) {
            return b;
        }
        if (this.isInfinity(b)) {
            return a;
        }

        // u = Y2 * Z1 - Y1 * Z2
        const u = this.subFE(this.mulFE(b.y, a.z), this.mulFE(a.y, b.z));
        // v = X2 * Z1 - X1 * Z2
        const v = this.subFE(this.mulFE(b.x, a.z), this.mulFE(a.x, b.z));

        if (this.isZero(v)) {
            if (this.isZero(u)) {
                return this.twiceEC(a); // a == b, so double
            }
            return this.getInfinity(a); // a = -b, so infinity
        }

        const x1 = a.x;
        const y1 = a.y;

        const v2 = this.sqrFE(v);
        const v3 = this.mulFE(v2, v);
        const x1v2 = this.mulFE(x1, v2);
        const zu2 = this.mulFE(this.sqrFE(u), a.z);

        // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
        const x3 = this.mulFE(this.subFE(this.mulFE(this.subFE(zu2, this.shlFE(x1v2, 1)), b.z), v3), v);
        // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
        const y3 = this.addFE(this.mulFE(this.subFE(this.subFE(this.mulFE(this.mulFE(x1v2, this.THREE), u), this.mulFE(y1, v3)), this.mulFE(zu2, u)), b.z), this.mulFE(u, v3));
        // z3 = v^3 * z1 * z2
        const z3 = this.mulFE(this.mulFE(v3, a.z), b.z);

        return this.newEC(a.curve, x3, y3, z3);
    }

    private twiceEC(b) {
        if (this.isInfinity(b)) {
            return b;
        }
        if (this.sig(b.y) === 0) {
            return this.getInfinity(b);
        }

        const x1 = b.x;
        const y1 = b.y;

        const y1z1 = this.mulFE(y1, b.z);
        const y1sqz1 = this.mulFE(y1z1, y1);
        const a = b.curve.a;

        // w = 3 * x1^2 + a * z1^2
        let w = this.mulFE(this.sqrFE(x1), this.THREE);
        if (!this.isZero(a)) {
            w = this.addFE(w, this.mulFE(this.sqrFE(b.z), a));
        }

        // x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
        const x3 = this.mulFE(this.shlFE(this.subFE(this.sqrFE(w), this.mulFE(this.shlFE(x1, 3), y1sqz1)), 1), y1z1);
        // y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
        const y3 = this.subFE(this.mulFE(this.shlFE(this.subFE(this.mulFE(this.mulFE(w, this.THREE), x1), this.shlFE(y1sqz1, 1)), 2), y1sqz1), this.mulFE(this.sqrFE(w), w));
        // z3 = 8 * (y1 * z1)^3
        const z3 = this.shlFE(this.mulFE(this.sqrFE(y1z1), y1z1), 3);

        return this.newEC(b.curve, x3, y3, z3);
    }

    // Simple NAF (Non-Adjacent Form) multiplication algorithm
    private mulEC(a, k) {
        if (this.isInfinity(a)) {
            return a;
        }
        if (this.sig(k) === 0) {
            return this.getInfinity(a);
        }

        const e = k;
        const h = this.mul(e, this.THREE);

        const neg = this.negEC(a);
        let R = a;

        let i;
        for (i = this.bitLength(h) - 2; i > 0; --i) {
            R = this.twiceEC(R);

            const hBit = this.testBit(h, i);
            const eBit = this.testBit(e, i);

            if (hBit !== eBit) {
                R = this.addEC(R, hBit ? a : neg);
            }
        }

        return R;
    }

    private mul2AndAddEC(a, k) {
        const nbits = this.bitLength(k);
        let R = a;
        let Q = this.getInfinity(a);

        for (let i = 0; i < nbits - 1; i++) {
            if (this.testBit(k, i) === true) { // FIXME не факт
                Q = this.addEC(Q, R);
            }

            R = this.twiceEC(R);
        }

        if (this.testBit(k, nbits - 1) === true) { // FIXME не факт
            Q = this.addEC(Q, R);
        }

        return Q;
    }

    // Compute a*j + x*k (simultaneous multiplication)
    private mulTwoEC(a, j, x, k) {
        let i;
        if (this.bitLength(j) > this.bitLength(k)) {
            i = this.bitLength(j) - 1;
        } else {
            i = this.bitLength(k) - 1;
        }

        let R = this.getInfinity(a);
        const both = this.addEC(a, x);
        while (i >= 0) {
            R = this.twiceEC(R);
            if (this.testBit(j, i)) {
                if (this.testBit(k, i)) {
                    R = this.addEC(R, both);
                } else {
                    R = this.addEC(R, a);
                }
            } else {
                if (this.testBit(k, i)) {
                    R = this.addEC(R, x);
                }
            }
            --i;
        }

        return R;
    }

    // EC Curve
    private newCurve(q, a, b) {
        const curve = new Curve();
        curve.q = q;
        curve.r = new Barrett(q, this);
        curve.a = this.newFE(curve, a);
        curve.b = this.newFE(curve, b);
        curve.infinity = this.newEC(curve, undefined, undefined, undefined);
        return curve;
    }


    private atobi(d) {
        const k = 8;
        const a = new Uint8Array(d);
        const r = this.nbi(a.length * 8 / this.DB);
        r.t = 0;
        r.s = 0;
        let sh = 0;
        for (let i = 0, n = a.length; i < n; i++) {
            const x = a[i];
            if (sh === 0) {
                r[r.t++] = x;
            } else if (sh + k > this.DB) {
                r[r.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
                r[r.t++] = (x >> (this.DB - sh));
            } else {
                r[r.t - 1] |= x << sh;
            }
            sh += k;
            if (sh >= this.DB) {
                sh -= this.DB;
            }
        }
        return this.clamp(r);
    }

    private bitoa(s, bitLength) {
        const k = 8;
        const km = (1 << k) - 1;
        let d;
        let m = false;
        const r = [];
        let i = s.t;
        let p = this.DB - (i * this.DB) % k;
        if (i-- > 0) {
            if (p < this.DB && (d = s[i] >> p) > 0) {
                m = true;
                r.push(d);
            }
            while (i >= 0) {
                if (p < k) {
                    d = (s[i] & ((1 << p) - 1)) << (k - p);
                    d |= s[--i] >> (p += this.DB - k);
                } else {
                    d = (s[i] >> (p -= k)) & km;
                    if (p <= 0) {
                        p += this.DB;
                        --i;
                    }
                }
                if (d > 0) {
                    m = true;
                }
                if (m) {
                    r.push(d);
                }
            }
        }
        const r8 = new Uint8Array(bitLength ? bitLength / 8 : r.length);
        if (m) {
            r8.set(r.reverse());
        }
        return r8.buffer;
    }


    private htobi(s) {
        if (typeof s === 'number' || s instanceof Number) {
            return this.nbv(s);
        }
        s = s.replace(/[^\-A-Fa-f0-9]/g, '');
        if (!s) {
            s = '0';
        }
        const k = 4;
        const r = this.nbi(s.length / 7);
        let i = s.length;
        let mi = false;
        let sh = 0;
        while (--i >= 0) {
            const c = s.charAt(i);
            if (c === '-') {
                mi = true;
                continue;
            }
            const x = parseInt(s.charAt(i), 16);
            mi = false;
            if (sh === 0) {
                r[r.t++] = x;
            } else if (sh + k > this.DB) {
                r[r.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
                r[r.t++] = (x >> (this.DB - sh));
            } else {
                r[r.t - 1] |= x << sh;
            }
            sh += k;
            if (sh >= this.DB) {
                sh -= this.DB;
            }
        }
        if (mi) {
            this.subTo(this.ZERO, r, r);
        }
        return this.clamp(r);
    }

    private bitoh(x) {
        if (x.s < 0) {
            return '-' + this.bitoh(this.negTo(x, this.nbi(x.t)));
        }
        const k = 4;
        const km = (1 << k) - 1;
        let d;
        let m = false;
        let r = '';
        let i = x.t;
        let p = this.DB - (i * this.DB) % k;
        if (i-- > 0) {
            if (p < this.DB && (d = x[i] >> p) > 0) {
                m = true;
                r = d.toString(16);
            }
            while (i >= 0) {
                if (p < k) {
                    d = (x[i] & ((1 << p) - 1)) << (k - p);
                    d |= x[--i] >> (p += this.DB - k);
                } else {
                    d = (x[i] >> (p -= k)) & km;
                    if (p <= 0) {
                        p += this.DB;
                        --i;
                    }
                }
                if (d > 0) {
                    m = true;
                }
                if (m) {
                    r += d.toString(16);
                }
            }
        }
        return '0x' + (m ? r : '0');
    }

    // biginteger to big-endian integer bytearray
    private bitoi(s) {
        let i = s.t;
        const r = [];
        r[0] = s.s;
        let p = this.DB - (i * this.DB) % 8;
        let d;
        let k = 0;
        if (i-- > 0) {
            if (p < this.DB && (d = s[i] >> p) !== (s.s & this.DM) >> p) {
                r[k++] = d | (s.s << (this.DB - p));
            }
            while (i >= 0) {
                if (p < 8) {
                    d = (s[i] & ((1 << p) - 1)) << (8 - p);
                    d |= s[--i] >> (p += this.DB - 8);
                } else {
                    d = (s[i] >> (p -= 8)) & 0xff;
                    if (p <= 0) {
                        p += this.DB;
                        --i;
                    }
                }
                if ((d & 0x80) !== 0) {
                    d |= -256;
                }
                if (k === 0 && (s.s & 0x80) !== (d & 0x80)) {
                    ++k;
                }
                if (k > 0 || d !== s.s) {
                    r[k++] = d;
                }
            }
        }
        return new Uint8Array(r).buffer;
    }

    // big-endian integer bytearray to biginteger
    private itobi(d) {
        const k = 8;
        const s = new Uint8Array(d);
        const r = this.nbi(s.length / 7);
        r.t = 0;
        r.s = 0;
        let i = s.length;
        let sh = 0;
        while (--i >= 0) {
            const x = s[i] & 0xff;
            if (sh === 0) {
                r[r.t++] = x;
            } else if (sh + k > this.DB) {
                r[r.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
                r[r.t++] = (x >> (this.DB - sh));
            } else {
                r[r.t - 1] |= x << sh;
            }
            sh += k;
            if (sh >= this.DB) {
                sh -= this.DB;
            }
        }
        if ((s[0] & 0x80) !== 0) {
            r.s = -1;
            if (sh > 0) {
                r[r.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
            }
        }
        return this.clamp(r);
    }


    // Swap bytes in buffer
    private swap(s) {
        const src = new Uint8Array(s);
        const dst = new Uint8Array(src.length);
        for (let i = 0, n = src.length; i < n; i++) {
            dst[n - i - 1] = src[i];
        }
        return dst.buffer;
    }



    // Check buffer
    private buffer(d) {
        if (d instanceof ArrayBuffer) {
            return d;
        } else if (d && d.buffer && d.buffer instanceof ArrayBuffer) {
            return d.byteOffset === 0 && d.byteLength === d.buffer.byteLength ?
                d.buffer : new Uint8Array(new Uint8Array(d, d.byteOffset, d.byteLength)).buffer;
        } else {
            throw new Error('ArrayBuffer or ArrayBufferView required');
        }
    }

    // Check double buffer
    private to2(d) {
        const b = this.buffer(d);
        if (b.byteLength % 2 > 0) {
            throw new Error('Buffer length must be even');
        }
        // tslint:disable-next-line:prefer-const
        let n = b.byteLength / 2;
        return [this.atobi(new Uint8Array(b, 0, n)), this.atobi(new Uint8Array(b, n, n))];
    }

    private from2(x, y, bitLength) {
        const a = this.bitoa(x, bitLength);
        const b = this.bitoa(y, bitLength);
        const d = new Uint8Array(a.byteLength + b.byteLength);
        d.set(new Uint8Array(a));
        d.set(new Uint8Array(b), a.byteLength);
        return d.buffer;
    }

    private getSeed(length) {
        const d = new Uint8Array(Math.ceil(length / 8));
        GostRandom.getRandomValues(d);
    }










    sign(privateKey, data) {

        // Stage 1
        const b = this.buffer(data);
        const alpha = this.atobi(this.hash( b));

        const q = this.q;
        const x = this.mod(this.atobi(this.buffer(privateKey)), q);

        // Stage 2
        let e = this.mod(alpha, q);
        if (this.isZero(e)) {
            e = this.ONE;
        }
        let r;
        let s = this.ZERO;
        let k;
        while (this.isZero(s)) {
            r = this.ZERO;
            while (this.isZero(r)) {

                // Stage 3
               k = this.mod(this.atobi(this.ukm ||
                    this.getSeed(this.bitLength)), q); // pseudo random 0 < k < q
                // Stage 4
               if (this.curve) {
                    // Gost R 34.10-2001 || Gost R 34.10-2012
                    const P = this.P;
                    const C = this.mulEC(P, k);
                    r = this.mod(this.getX(C), q);
                } else {
                    // Gost R 34.10-94
                    const p = this.p;
                    const a = this.a;
                    r = this.mod(this.expMod(a, k, p), q);
                }
            }
            // Stage 5
            s = this.mod(this.add(this.mul(r, x), this.mul(k, e)), q);
        }
        // Stage 6
        // console.log('s', bitoh(s));
        // console.log('r', bitoh(r));
        let zetta;
        // Integer structure for SignalCom algorithm
        if (this.procreator === 'SC') {
            zetta = {
                r: this.bitoh(r),
                s: this.bitoh(s)
            };
        } else {
            zetta = this.from2(r, s, this.bitLength);
            // Swap bytes for CryptoPro algorithm
            if (this.procreator === 'CP' || this.procreator === 'VN') {
                zetta = this.swap(zetta);
            }
        }
        return zetta;
    }


    verify(publicKey, signature, data) {

        // Stage 1
        const q = this.q;
        let r;
        let s;
        // Ready int for SignalCom algorithm
        if (this.procreator === 'SC') {
            r = this.htobi(signature.r);
            s = this.htobi(signature.s);
        } else {
            if (this.procreator === 'CP' || this.procreator === 'VN') {
                signature = this.swap(signature);
            }
            const zetta = this.to2(signature);
            // Swap bytes for CryptoPro algorithm
            s = zetta[1]; //  first 32 octets contain the big-endian representation of s
            r = zetta[0]; //  and second 32 octets contain the big-endian representation of r
        }
        if (this.compare(r, q) >= 0 || this.compare(s, q) >= 0) {
            return false;
        }
        // Stage 2
        const b = this.buffer(data);
        const alpha = this.atobi(this.hash( b));
        // Stage 3
        let e = this.mod(alpha, q);
        if (this.isZero(e) === false) {
            e = this.ONE;
        }
        // Stage 4
        const v = this.invMod(e, q);
        // Stage 5
        const z1 = this.mod(this.mul(s, v), q);
        const z2 = this.sub(q, this.mod(this.mul(r, v), q));
        // Stage 6
        let R;
        if (this.curve) {
            // Gost R 34.10-2001 || Gost R 34.10-2012
            const k2 = this.to2(publicKey);
            const curve = this.curve;
            const P = this.P;
            const x = this.newFE(curve, k2[0]);
// first 32 octets contain the little-endian representation of x
            const y = this.newFE(curve, k2[1]);
// and second 32 octets contain the little-endian representation of y.
            const Q = this.newEC(curve, x, y, undefined);

 // This corresponds to the binary representation of (<y>256||<x>256)
            const C = this.mulTwoEC(P, z1, Q, z2);
            R = this.mod(this.getX(C), q);
        } else {
            // Gost R 34.10-94
            const p = this.p;
            const a = this.a;
            const y = this.atobi(publicKey);
            R = this.mod(this.mod(this.mul(this.expMod(a, z1, p), this.expMod(y, z2, p)), p), q);
        }
        // Stage 7
        return (this.compare(R, r) === 0);
    }

    generateKey() {
        const curve = this.curve;
        if (curve) {
            let d = this.ZERO;
            let Q = curve.infinity;
            let x;
            let y;
            while (this.isInfinity(Q)) {

                // Generate random private key

                if (this.ukm) {
                    d = this.atobi(this.ukm);
                } else {
                    while (this.isZero(d)) {
                        d = this.mod(this.atobi(this.getSeed(this.bitLength)), this.q);
                    } // 0 < d < q
                }

                // Calculate public key
                Q = this.mulEC(this.P, d);
                x = this.getX(Q);
                y = this.getY(Q);
                // console.log('d', bitoh(d));
                // console.log('x', bitoh(x));
                // console.log('y', bitoh(y));
            }

            // Return result
            return {
                privateKey: this.bitoa(d, this.bitLength),
                publicKey: this.from2(x, y, this.bitLength) // This corresponds to the binary representation of (<y>256||<x>256)
            };

        } else {
            throw new Error('Key generation for GOST R 34.10-94 not supported');
        }
    }

    private generateMaskKey() {
        const curve = this.curve;
        if (curve) {
            // Generate random private key
            let d = this.ZERO;
            while (this.isZero(d)) {
                d = this.mod(this.atobi(this.getSeed(this.bitLength)), this.q);
            } // 0 < d < q

            // Return result
            return this.bitoa(d, this.bitLength);
        } else {
            throw new Error('Key generation for GOST R 34.10-94 not supported');
        }
    }

    private unwrapKey(baseKey, data) {
        const curve = this.curve;
        if (curve) {
            const q = this.q;
            const x = this.mod(this.atobi(this.buffer(data)), q);
            const y = this.mod(this.atobi(this.buffer(baseKey)), q);
            const z = this.procreator === 'VN' ? this.mod(this.mul(x, y), q) : this.mod(this.mul(x, this.invMod(y, q)), q);
            return this.bitoa(z, undefined);
        } else {
            throw new Error('Key wrapping GOST R 34.10-94 not supported');
        }
    }

    private wrapKey(baseKey, data) {
        const curve = this.curve;
        if (curve) {
            const q = this.q;
            const x = this.mod(this.atobi(this.buffer(data)), q);
            const y = this.mod(this.atobi(this.buffer(baseKey)), q);
            const z = this.procreator === 'VN' ? this.mod(this.mul(x, this.invMod(y, q)), q) : this.mod(this.mul(x, y), q);
            return this.bitoa(z, undefined);
        } else {
            throw new Error('Key wrapping GOST R 34.10-94 not supported');
        }
    }
    private derive(baseKey) {

        let k;
        const ukm = this.atobi(this.ukm);
        const q = this.q;
        const x = this.mod(this.atobi(this.buffer(baseKey)), q);

        if (this.curve) {
            // 1) Let K(x,y,UKM) = ((UKM*x)(mod q)) . (y.P) (512 bit), where
            // x - sender’s private key (256 bit)
            // x.P - sender’s public key (512 bit)
            // y - recipient’s private key (256 bit)
            // y.P - recipient’s public key (512 bit)
            // UKM - non-zero integer, produced as in step 2 p. 6.1 [GOSTR341001]
            // P - base point on the elliptic curve (two 256-bit coordinates)
            // UKM*x - x multiplied by UKM as integers
            // x.P - a multiple point
            const K = this.mulEC(this.peer_Q, this.mod(this.mul(ukm, x), q));
            k = this.from2(this.getX(K), this.getY(K), // This corresponds to the binary representation of (<y>256||<x>256)
                this.bitLength);
        } else {
            // 1) Let K(x,y) = a^(x*y) (mod p), where
            // x - sender’s private key, a^x - sender’s public key
            // y - recipient’s private key, a^y - recipient’s public key
            // a, p - parameters
            const p = this.p;
            const a = this.a;
            k = this.bitoa(this.expMod(this.peer_y, x, p), undefined);
        }
        // 2) Calculate a 256-bit hash of K(x,y,UKM):
        // KEK(x,y,UKM) = gostSign (K(x,y,UKM)
        return this.hash( k);
    }

    hash(d) {
        if (this.dostDigest) {
            d = this.dostDigest.digest(d);
        }
        // Swap hash for SignalCom
        if (this.procreator === 'SC' ||
            (this.procreator === 'VN' && this.version === 2012)) {
            d = this.swap(d);
        }
        return d;
    }
    private deriveBits(baseKey, length) {
        if (length < 8 || length > this.bitLength || length % 8 > 0) {
            throw new Error('Length must be no more than ' + this.bitLength + ' bits and multiple of 8');
        }
        const n = length / 8;
        const b = this.derive(baseKey);
        const r = new Uint8Array(n);

        r.set(new Uint8Array(b, 0, n));
        return r.buffer;
    } // </editor-fold>

    private deriveKey(baseKey) {
        const b = this.derive(baseKey);
        const r = new Uint8Array(32);

        r.set(new Uint8Array(b, 0, 32));
        return r.buffer;
    } 






















}

class Curve {
    q;
    r;
    a;
    b;
    infinity;
}

class Classic {
    m;
    convert;
    revert;
    reduce;
    sqrTo;
    mulTo;

    constructor(m, private gostSign: GostSign) {
        this.m = m;
        this.convert = (x) => {
            if (x.s < 0 || gostSign.compare(x, this.m) >= 0) {
                return gostSign.mod(x, this.m);
            } else {
                return x;
            }
        };

        this.revert = (x) => gostSign.nothing(x);

        this.reduce = (x) => {
            gostSign.modTo(x, this.m, x);
        };
        this.sqrTo = (x, r) => {
            gostSign.sqrTo(x, r);
            this.reduce(r);
        };
        this.mulTo = (x, y, r) => {
            gostSign.mulTo(x, y, r);
            this.reduce(r);
        };
    }
}

class Montgomery {
    m;
    mp;
    mpl;
    mph;
    um;
    mt2;

    constructor(m, private gostSign: GostSign) {
        this.m = m;
        this.mp = gostSign.invDig(m);
        this.mpl = this.mp & 0x7fff;
        this.mph = this.mp >> 15;
        this.um = (1 << (gostSign.DB - 15)) - 1;
        this.mt2 = 2 * m.t;
    }
}

class Barrett {
    m;
    private revert: (x) => any;
    private convert: (x) => (any | any | any);
    private reduce: (x) => void;
    private sqrTo: (x, r) => void;
    private mulTo: (x, y, r) => void;
    private r2: any;
    private q3: any;
    private mu: any;

    constructor(m, private gostSign: GostSign) {
        this.r2 = gostSign.nbi(2 * m.t);
        this.q3 = gostSign.nbi(2 * m.t);
        gostSign.dshlTo(gostSign.ONE, 2 * m.t, this.r2);
        this.mu = gostSign.div(this.r2, m);
        this.m = m;


        this.convert = (x) => {
            if (x.s < 0 || x.t > 2 * this.m.t) {
                return gostSign.mod(x, this.m);
            } else if (gostSign.compare(x, this.m) < 0) {
                return x;
            } else {
                const r = gostSign.nbi(x.t);
                gostSign.copyTo(x, r);
                this.reduce(r);
                return r;
            }
        };
        this.revert = (x) => {
            return x;
        };
        // x = x mod m (HAC 14.42)
        this.reduce = (x) => {
            gostSign.dshrTo(x, this.m.t - 1, this.r2);
            if (x.t > this.m.t + 1) {
                x.t = this.m.t + 1;
                gostSign.clamp(x);
            }
            gostSign.mulUpperTo(this.mu, this.r2, this.m.t + 1, this.q3);
            gostSign.mulLowerTo(this.m, this.q3, this.m.t + 1, this.r2);
            while (gostSign.compare(x, this.r2) < 0) {
                gostSign.dAddOffset(x, 1, this.m.t + 1);
            }
            gostSign.subTo(x, this.r2, x);
            while (gostSign.compare(x, this.m) >= 0) {
                gostSign.subTo(x, this.m, x);
            }
        };
        // r = x^2 mod m; x != r
        this.sqrTo = (x, r) => {
            gostSign.sqrTo(x, r);
            this.reduce(r);
        };
        // r = x*y mod m; x,y != r
        this.mulTo = (x, y, r) => {
            gostSign.mulTo(x, y, r);
            this.reduce(r);
        };


    }
}
