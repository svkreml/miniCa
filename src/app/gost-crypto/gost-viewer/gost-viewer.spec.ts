import {GostViewer} from './gost-viewer';
import {Syntax} from './syntax';
import {BERElement} from 'asn1-ts';
import {Base64, GostCoding, PEM} from '../gost-coding/gost-coding';
import {BERtypes} from './BERTypes';

describe('GostViewer', () => {
    let certRsa: string =
        'MIIEdjCCBCOgAwIBAgIBATAKBggqhQMHAQEDAjCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Qn9C1\n' +
        '0YLQtdGA0LHRg9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0GA1UE\n' +
        'CwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7MDkG\n' +
        'A1UEAwwy0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L0wHhcNMTQxMjA0MjEwMDAw\n' +
        'WhcNMzQxMjA0MjEwMDAwWjCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Qn9C10YLQtdGA0LHRg9GA\n' +
        '0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0GA1UECwwW0KDRg9C60L7Q\n' +
        'stC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7MDkGA1UEAwwy0JDQu9C1\n' +
        '0LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L0wZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggq\n' +
        'hQMHAQECAgNDAARAQUCQNg5eYYIcxtaREQRxu/DjXzHflHl+6V0k62fEOKHFqiPC/zO6lSd5Nm6an8Z28owrasJdYX/B8xBQ\n' +
        'NDVnG6OCAZswggGXMA4GA1UdDwEBAQQEAwIB/jAxBgNVHSUEKjAoBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggr\n' +
        'BgEFBQcDBDAPBgNVHRMBAQEEBTADAQEBMB0GA1UdDgQWBBSdYVnKqBWdaajYbstN3tOx3IvQszCCASAGA1UdIwSCARcwggET\n' +
        'gBSdYVnKqBWdaajYbstN3tOx3IvQs6GB96SB9DCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Qn9C1\n' +
        '0YLQtdGA0LHRg9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0GA1UE\n' +
        'CwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7MDkG\n' +
        'A1UEAwwy0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L2CAQEwCgYIKoUDBwEBAwID\n' +
        'QQAEv5zJHKm0mhANAf+AtQ0c73VAvtldxhH2rUBxUBt5BDc2OZBpjsw7uFnK0W6EXRmrEVuVzcspeGIsjYOtTBNa\n';
    let certRsaAsn1: string = '    0 30 1142: SEQUENCE {\n' +
        '    4 30 1059:  SEQUENCE {\n' +
        '    8 a0    3:   [0] {\n' +
        '   10 02    1:    INTEGER 2\n' +
        '             :   }\n' +
        '   13 02    1:   INTEGER 1\n' +
        '   16 30   10:   SEQUENCE {\n' +
        '   18 06    8:    OBJECT IDENTIFIER id-tc26-signwithdigest-gost3410-12-256 (1.2.643.7.1.1.3.2)\n' +
        '             :   }\n' +
        '   28 30  241:   SEQUENCE {\n' +
        '   31 31   11:    SET {\n' +
        '   33 30    9:     SEQUENCE {\n' +
        '   35 06    3:      OBJECT IDENTIFIER countryName (2.5.4.6)\n' +
        '   40 13    2:      PrintableString "RU"\n' +
        '             :     }\n' +
        '             :    }\n' +
        '   44 31   42:    SET {\n' +
        '   46 30   40:     SEQUENCE {\n' +
        '   48 06    3:      OBJECT IDENTIFIER stateOrProvinceName (2.5.4.8)\n' +
        '   53 0c   33:      UTF8String "Санктъ-Петербургъ"\n' +
        '             :     }\n' +
        '             :    }\n' +
        '   88 31   46:    SET {\n' +
        '   90 30   44:     SEQUENCE {\n' +
        '   92 06    3:      OBJECT IDENTIFIER organizationName (2.5.4.10)\n' +
        '   97 0c   37:      UTF8String "Журнал "Современник""\n' +
        '             :     }\n' +
        '             :    }\n' +
        '  136 31   31:    SET {\n' +
        '  138 30   29:     SEQUENCE {\n' +
        '  140 06    3:      OBJECT IDENTIFIER organizationalUnitName (2.5.4.11)\n' +
        '  145 0c   22:      UTF8String "Руководство"\n' +
        '             :     }\n' +
        '             :    }\n' +
        '  169 31   40:    SET {\n' +
        '  171 30   38:     SEQUENCE {\n' +
        '  173 06    3:      OBJECT IDENTIFIER title (2.5.4.12)\n' +
        '  178 0c   31:      UTF8String "Главный редактор"\n' +
        '             :     }\n' +
        '             :    }\n' +
        '  211 31   59:    SET {\n' +
        '  213 30   57:     SEQUENCE {\n' +
        '  215 06    3:      OBJECT IDENTIFIER commonName (2.5.4.3)\n' +
        '  220 0c   50:      UTF8String "Александр Сергеевич Пушкин"\n' +
        '             :     }\n' +
        '             :    }\n' +
        '             :   }\n' +
        '  272 30   30:   SEQUENCE {\n' +
        '  274 17   13:    UTCTime Fri Dec 05 2014 00:00:00 GMT+0300 (Москва, стандартное время)\n' +
        '  289 17   13:    UTCTime Tue Dec 05 2034 00:00:00 GMT+0300 (Москва, стандартное время)\n' +
        '             :   }\n' +
        '  304 30  241:   SEQUENCE {\n' +
        '  307 31   11:    SET {\n' +
        '  309 30    9:     SEQUENCE {\n' +
        '  311 06    3:      OBJECT IDENTIFIER countryName (2.5.4.6)\n' +
        '  316 13    2:      PrintableString "RU"\n' +
        '             :     }\n' +
        '             :    }\n' +
        '  320 31   42:    SET {\n' +
        '  322 30   40:     SEQUENCE {\n' +
        '  324 06    3:      OBJECT IDENTIFIER stateOrProvinceName (2.5.4.8)\n' +
        '  329 0c   33:      UTF8String "Санктъ-Петербургъ"\n' +
        '             :     }\n' +
        '             :    }\n' +
        '  364 31   46:    SET {\n' +
        '  366 30   44:     SEQUENCE {\n' +
        '  368 06    3:      OBJECT IDENTIFIER organizationName (2.5.4.10)\n' +
        '  373 0c   37:      UTF8String "Журнал "Современник""\n' +
        '             :     }\n' +
        '             :    }\n' +
        '  412 31   31:    SET {\n' +
        '  414 30   29:     SEQUENCE {\n' +
        '  416 06    3:      OBJECT IDENTIFIER organizationalUnitName (2.5.4.11)\n' +
        '  421 0c   22:      UTF8String "Руководство"\n' +
        '             :     }\n' +
        '             :    }\n' +
        '  445 31   40:    SET {\n' +
        '  447 30   38:     SEQUENCE {\n' +
        '  449 06    3:      OBJECT IDENTIFIER title (2.5.4.12)\n' +
        '  454 0c   31:      UTF8String "Главный редактор"\n' +
        '             :     }\n' +
        '             :    }\n' +
        '  487 31   59:    SET {\n' +
        '  489 30   57:     SEQUENCE {\n' +
        '  491 06    3:      OBJECT IDENTIFIER commonName (2.5.4.3)\n' +
        '  496 0c   50:      UTF8String "Александр Сергеевич Пушкин"\n' +
        '             :     }\n' +
        '             :    }\n' +
        '             :   }\n' +
        '  548 30  102:   SEQUENCE {\n' +
        '  550 30   31:    SEQUENCE {\n' +
        '  552 06    8:     OBJECT IDENTIFIER id-tc26-gost3410-12-256 (1.2.643.7.1.1.1.1)\n' +
        '  562 30   19:     SEQUENCE {\n' +
        '  564 06    7:      OBJECT IDENTIFIER id-GostR3410-2001-CryptoPro-XchA-ParamSet (1.2.643.2.2.36.0)\n' +
        '  573 06    8:      OBJECT IDENTIFIER id-tc26-gost3411-12-256 (1.2.643.7.1.1.2.2)\n' +
        '             :     }\n' +
        '             :    }\n' +
        '  583 03   67:    BIT STRING, unused 0 bits, encapsulates {\n' +
        '  585 04   64:     OCTET STRING\n' +
        '             :      41 40 90 36 0e 5e 61 82 1c c6 d6 91 11 04 71 bb\n' +
        '             :      f0 e3 5f 31 df 94 79 7e e9 5d 24 eb 67 c4 38 a1\n' +
        '             :      c5 aa 23 c2 ff 33 ba 95 27 79 36 6e 9a 9f c6 76\n' +
        '             :      f2 8c 2b 6a c2 5d 61 7f c1 f3 10 50 34 35 67 1b\n' +
        '             :    }\n' +
        '             :   }\n' +
        '  652 a3  411:   [3] {\n' +
        '  656 30  407:    SEQUENCE {\n' +
        '  660 30   14:     SEQUENCE {\n' +
        '  662 06    3:      OBJECT IDENTIFIER keyUsage (2.5.29.15)\n' +
        '  667 01    1:      BOOLEAN true\n' +
        '  670 04    4:      OCTET STRING, encapsulates {\n' +
        '  672 03    2:       BIT STRING, unused 1 bits\n' +
        '             :        1111111B\n' +
        '             :      }\n' +
        '             :     }\n' +
        '  676 30   49:     SEQUENCE {\n' +
        '  678 06    3:      OBJECT IDENTIFIER extKeyUsage (2.5.29.37)\n' +
        '  683 04   42:      OCTET STRING, encapsulates {\n' +
        '  685 30   40:       SEQUENCE {\n' +
        '  687 06    8:        OBJECT IDENTIFIER serverAuth (1.3.6.1.5.5.7.3.1)\n' +
        '  697 06    8:        OBJECT IDENTIFIER clientAuth (1.3.6.1.5.5.7.3.2)\n' +
        '  707 06    8:        OBJECT IDENTIFIER codeSigning (1.3.6.1.5.5.7.3.3)\n' +
        '  717 06    8:        OBJECT IDENTIFIER emailProtection (1.3.6.1.5.5.7.3.4)\n' +
        '             :       }\n' +
        '             :      }\n' +
        '             :     }\n' +
        '  727 30   15:     SEQUENCE {\n' +
        '  729 06    3:      OBJECT IDENTIFIER basicConstraints (2.5.29.19)\n' +
        '  734 01    1:      BOOLEAN true\n' +
        '  737 04    5:      OCTET STRING, encapsulates {\n' +
        '  739 30    3:       SEQUENCE {\n' +
        '  741 01    1:        BOOLEAN true\n' +
        '             :       }\n' +
        '             :      }\n' +
        '             :     }\n' +
        '  744 30   29:     SEQUENCE {\n' +
        '  746 06    3:      OBJECT IDENTIFIER subjectKeyIdentifier (2.5.29.14)\n' +
        '  751 04   22:      OCTET STRING, encapsulates {\n' +
        '  753 04   20:       OCTET STRING\n' +
        '             :        9d 61 59 ca a8 15 9d 69 a8 d8 6e cb 4d de d3 b1\n' +
        '             :        dc 8b d0 b3\n' +
        '             :      }\n' +
        '             :     }\n' +
        '  775 30  288:     SEQUENCE {\n' +
        '  779 06    3:      OBJECT IDENTIFIER authorityKeyIdentifier (2.5.29.35)\n' +
        '  784 04  279:      OCTET STRING, encapsulates {\n' +
        '  788 30  275:       SEQUENCE {\n' +
        '  792 80   20:        [0]\n' +
        '             :         9d 61 59 ca a8 15 9d 69 a8 d8 6e cb 4d de d3 b1\n' +
        '             :         dc 8b d0 b3\n' +
        '  814 a1  247:        [1] {\n' +
        '  817 a4  244:         [4] {\n' +
        '  820 30  241:          SEQUENCE {\n' +
        '  823 31   11:           SET {\n' +
        '  825 30    9:            SEQUENCE {\n' +
        '  827 06    3:             OBJECT IDENTIFIER countryName (2.5.4.6)\n' +
        '  832 13    2:             PrintableString "RU"\n' +
        '             :            }\n' +
        '             :           }\n' +
        '  836 31   42:           SET {\n' +
        '  838 30   40:            SEQUENCE {\n' +
        '  840 06    3:             OBJECT IDENTIFIER stateOrProvinceName (2.5.4.8)\n' +
        '  845 0c   33:             UTF8String "Санктъ-Петербургъ"\n' +
        '             :            }\n' +
        '             :           }\n' +
        '  880 31   46:           SET {\n' +
        '  882 30   44:            SEQUENCE {\n' +
        '  884 06    3:             OBJECT IDENTIFIER organizationName (2.5.4.10)\n' +
        '  889 0c   37:             UTF8String "Журнал "Современник""\n' +
        '             :            }\n' +
        '             :           }\n' +
        '  928 31   31:           SET {\n' +
        '  930 30   29:            SEQUENCE {\n' +
        '  932 06    3:             OBJECT IDENTIFIER organizationalUnitName (2.5.4.11)\n' +
        '  937 0c   22:             UTF8String "Руководство"\n' +
        '             :            }\n' +
        '             :           }\n' +
        '  961 31   40:           SET {\n' +
        '  963 30   38:            SEQUENCE {\n' +
        '  965 06    3:             OBJECT IDENTIFIER title (2.5.4.12)\n' +
        '  970 0c   31:             UTF8String "Главный редактор"\n' +
        '             :            }\n' +
        '             :           }\n' +
        ' 1003 31   59:           SET {\n' +
        ' 1005 30   57:            SEQUENCE {\n' +
        ' 1007 06    3:             OBJECT IDENTIFIER commonName (2.5.4.3)\n' +
        ' 1012 0c   50:             UTF8String "Александр Сергеевич Пушкин"\n' +
        '             :            }\n' +
        '             :           }\n' +
        '             :          }\n' +
        '             :         }\n' +
        '             :        }\n' +
        ' 1064 82    1:        [2]\n' +
        '             :         01\n' +
        '             :       }\n' +
        '             :      }\n' +
        '             :     }\n' +
        '             :    }\n' +
        '             :   }\n' +
        '             :  }\n' +
        ' 1067 30   10:  SEQUENCE {\n' +
        ' 1069 06    8:   OBJECT IDENTIFIER id-tc26-signwithdigest-gost3410-12-256 (1.2.643.7.1.1.3.2)\n' +
        '             :  }\n' +
        ' 1079 03   65:  BIT STRING, unused 0 bits\n' +
        '             :   04 bf 9c c9 1c a9 b4 9a 10 0d 01 ff 80 b5 0d 1c\n' +
        '             :   ef 75 40 be d9 5d c6 11 f6 ad 40 71 50 1b 79 04\n' +
        '             :   37 36 39 90 69 8e cc 3b b8 59 ca d1 6e 84 5d 19\n' +
        '             :   ab 11 5b 95 cd cb 29 78 62 2c 8d 83 ad 4c 13 5a\n' +
        '             : }';

    let pkeyRsa: string = '-----BEGIN PRIVATE KEY-----\n' +
        'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDcMqBoUV2ZiqhbpGr0Dfcmeo/B2NpAF43jTzeTCiNCco78WvOVRYU22F9F7r+V+DnALPJ6APhxaS73u8LnQe+gpnReTXXGVG8KZFgQUOyg4jGMx/Y9RjTZE5bQgWSpzf3Bz+ehi7lRjgc8Og6esAUEnv9O0lQad07JLiJelRelweFxvJmH3qNYBk1N8rCiIIhrWyQ0w7asaqypydvWVzUSGRPoPPj3oZjtg4ABlYXLY/y9F7ByDeSkpA2953Sjmdt2JR+u8rSl/5WJTQp7Kxw+Z3QYIn/wju2BmF5kZZYG9xDe99vXIMMNQR0iBQQstnNa4dFaI24UkewJ6MS5ZiY5AgMBAAECggEAE/V8Iq3VXRh7YCshYqkYEOMlFVNcR65FjH1esojwXz0rsWYRFCOutSTxpdDD3t/BZFDuqEO0QUYLyCVlv45zc6Ktg5Vj1Sv2u1YTFrovE094DE8HsSV5ntTZY7bcHU7FmdlddoAdYRi4QSubWE4+IN1vPiwZts2/qhlGFj/6BRUdqisPrTP/WVj2JI0AJWR1gDK9degTuqLP/5nGdy0a7kE4A/BjQX9mn+wPP4+bxRQHdp9RQgSdTMi0lY2KXSrYAcfOQzqzEPsu+FWuS4/0R1Eq7h+L/kGyNjmRvOhvUmJPgQqh4Mo+FF0PapmY7J+jsK7s7OgYzGcYn64Xq0W9DQKBgQD+NyCf+ul9pEFnuGk3gVydWYJundvE75Z7smxjsXjQWvVFnW52mDxo+M1/Vvz0Dvhu0Mtrzjn9k7C0e3Y8+E8vH5Lp3g9Z7MJQnuM36mzH/grr9s1BRmbtx+RgCZTulWOfPpcapkVCk6CCOFxEcfP9bqR5AJvCg1pZ0ZJtqXiF/wKBgQDdvlz57VUjv4Gh/R4MwVrqBX8dXReYNmQ7NIM7dCOr7ALiQLvXNA5nEzxoxabOIDzCJAeM/yqYs7E5h8NCjln6lii2FIjtiLe7ywa/iRrY1/6Ldvir1VYw8YyxPKBoADyrVIZD7G5u93lIdR1e6eyx3mTWUwWJCnLPxQqBlNwDxwKBgDJZUMjetSgBREL6rzwjDujLNZ4a/c//c9qD+Bu2pqr9mN5009ABTtWrkWfLHsZnwKSSDfgIHEww2Cqm2UAyHdzDcCGJrZit375/+Zi1gV4K3rblZrmq6+/kS0MKIskuJVEA4ISSsd0ByCSCbSPRPfXP2BtvF2prAZYQf+PgUNKZAoGBAMbPcb8nWimF/21EaxfWmHOv3+ts1sXDJpSqnWrF02HGZkOC9KebZbpm1ce+RrMS1kbeVOLGuONWYPSK07ett+DjlrbBrI8EAG/gNTmvbKG07uUOEyDFUtTpDVKvX8Y/SCX4z7TAm7bkLRqY3m+F3pEPK2u53gGjm5LLQIMz+xtrAoGAJ77j4Qzt/gmQvsveD9QG2OWmFAcyxjevUUcqBJKt8U1TX2PY3VV0sHdmtvUK0IgDzlY7AWv4i/Ac0Xm0Jp6PZiC2GOSZh9Z3lhOdtcZIeGJFUHlDYK5BGLIZQvG0nCM4UfCuIKGg0hopV0WxEou8qgu0cESe1DxbCtUaaqxJ8t0=\n' +
        '-----END PRIVATE KEY-----';
    let pkeyRsaAsn1: string =
        '    0 30 1213: SEQUENCE {\n' +
        '    4 02    1:  INTEGER 0\n' +
        '    7 30   13:  SEQUENCE {\n' +
        '    9 06    9:   OBJECT IDENTIFIER rsaEncryption (1.2.840.113549.1.1.1)\n' +
        '   20 05    0:   NULL\n' +
        '             :  }\n' +
        '   22 04 1191:  OCTET STRING, encapsulates {\n' +
        '   26 30 1187:   SEQUENCE {\n' +
        '   30 02    1:    INTEGER 0\n' +
        '   33 02  257:    INTEGER\n' +
        '             :     00 dc 32 a0 68 51 5d 99 8a a8 5b a4 6a f4 0d f7\n' +
        '             :     26 7a 8f c1 d8 da 40 17 8d e3 4f 37 93 0a 23 42\n' +
        '             :     72 8e fc 5a f3 95 45 85 36 d8 5f 45 ee bf 95 f8\n' +
        '             :     39 c0 2c f2 7a 00 f8 71 69 2e f7 bb c2 e7 41 ef\n' +
        '             :     a0 a6 74 5e 4d 75 c6 54 6f 0a 64 58 10 50 ec a0\n' +
        '             :     e2 31 8c c7 f6 3d 46 34 d9 13 96 d0 81 64 a9 cd\n' +
        '             :     fd c1 cf e7 a1 8b b9 51 8e 07 3c 3a 0e 9e b0 05\n' +
        '             :     04 9e ff 4e d2 54 1a 77 4e c9 2e 22 5e 95 17 a5\n' +
        '             :     c1 e1 71 bc 99 87 de a3 58 06 4d 4d f2 b0 a2 20\n' +
        '             :     88 6b 5b 24 34 c3 b6 ac 6a ac a9 c9 db d6 57 35\n' +
        '             :     12 19 13 e8 3c f8 f7 a1 98 ed 83 80 01 95 85 cb\n' +
        '             :     63 fc bd 17 b0 72 0d e4 a4 a4 0d bd e7 74 a3 99\n' +
        '             :     db 76 25 1f ae f2 b4 a5 ff 95 89 4d 0a 7b 2b 1c\n' +
        '             :     3e 67 74 18 22 7f f0 8e ed 81 98 5e 64 65 96 06\n' +
        '             :     f7 10 de f7 db d7 20 c3 0d 41 1d 22 05 04 2c b6\n' +
        '             :     73 5a e1 d1 5a 23 6e 14 91 ec 09 e8 c4 b9 66 26\n' +
        '             :     39\n' +
        '  294 02    3:    INTEGER 65537\n' +
        '  299 02  256:    INTEGER\n' +
        '             :     13 f5 7c 22 ad d5 5d 18 7b 60 2b 21 62 a9 18 10\n' +
        '             :     e3 25 15 53 5c 47 ae 45 8c 7d 5e b2 88 f0 5f 3d\n' +
        '             :     2b b1 66 11 14 23 ae b5 24 f1 a5 d0 c3 de df c1\n' +
        '             :     64 50 ee a8 43 b4 41 46 0b c8 25 65 bf 8e 73 73\n' +
        '             :     a2 ad 83 95 63 d5 2b f6 bb 56 13 16 ba 2f 13 4f\n' +
        '             :     78 0c 4f 07 b1 25 79 9e d4 d9 63 b6 dc 1d 4e c5\n' +
        '             :     99 d9 5d 76 80 1d 61 18 b8 41 2b 9b 58 4e 3e 20\n' +
        '             :     dd 6f 3e 2c 19 b6 cd bf aa 19 46 16 3f fa 05 15\n' +
        '             :     1d aa 2b 0f ad 33 ff 59 58 f6 24 8d 00 25 64 75\n' +
        '             :     80 32 bd 75 e8 13 ba a2 cf ff 99 c6 77 2d 1a ee\n' +
        '             :     41 38 03 f0 63 41 7f 66 9f ec 0f 3f 8f 9b c5 14\n' +
        '             :     07 76 9f 51 42 04 9d 4c c8 b4 95 8d 8a 5d 2a d8\n' +
        '             :     01 c7 ce 43 3a b3 10 fb 2e f8 55 ae 4b 8f f4 47\n' +
        '             :     51 2a ee 1f 8b fe 41 b2 36 39 91 bc e8 6f 52 62\n' +
        '             :     4f 81 0a a1 e0 ca 3e 14 5d 0f 6a 99 98 ec 9f a3\n' +
        '             :     b0 ae ec ec e8 18 cc 67 18 9f ae 17 ab 45 bd 0d\n' +
        '  559 02  129:    INTEGER\n' +
        '             :     00 fe 37 20 9f fa e9 7d a4 41 67 b8 69 37 81 5c\n' +
        '             :     9d 59 82 6e 9d db c4 ef 96 7b b2 6c 63 b1 78 d0\n' +
        '             :     5a f5 45 9d 6e 76 98 3c 68 f8 cd 7f 56 fc f4 0e\n' +
        '             :     f8 6e d0 cb 6b ce 39 fd 93 b0 b4 7b 76 3c f8 4f\n' +
        '             :     2f 1f 92 e9 de 0f 59 ec c2 50 9e e3 37 ea 6c c7\n' +
        '             :     fe 0a eb f6 cd 41 46 66 ed c7 e4 60 09 94 ee 95\n' +
        '             :     63 9f 3e 97 1a a6 45 42 93 a0 82 38 5c 44 71 f3\n' +
        '             :     fd 6e a4 79 00 9b c2 83 5a 59 d1 92 6d a9 78 85\n' +
        '             :     ff\n' +
        '  691 02  129:    INTEGER\n' +
        '             :     00 dd be 5c f9 ed 55 23 bf 81 a1 fd 1e 0c c1 5a\n' +
        '             :     ea 05 7f 1d 5d 17 98 36 64 3b 34 83 3b 74 23 ab\n' +
        '             :     ec 02 e2 40 bb d7 34 0e 67 13 3c 68 c5 a6 ce 20\n' +
        '             :     3c c2 24 07 8c ff 2a 98 b3 b1 39 87 c3 42 8e 59\n' +
        '             :     fa 96 28 b6 14 88 ed 88 b7 bb cb 06 bf 89 1a d8\n' +
        '             :     d7 fe 8b 76 f8 ab d5 56 30 f1 8c b1 3c a0 68 00\n' +
        '             :     3c ab 54 86 43 ec 6e 6e f7 79 48 75 1d 5e e9 ec\n' +
        '             :     b1 de 64 d6 53 05 89 0a 72 cf c5 0a 81 94 dc 03\n' +
        '             :     c7\n' +
        '  823 02  128:    INTEGER\n' +
        '             :     32 59 50 c8 de b5 28 01 44 42 fa af 3c 23 0e e8\n' +
        '             :     cb 35 9e 1a fd cf ff 73 da 83 f8 1b b6 a6 aa fd\n' +
        '             :     98 de 74 d3 d0 01 4e d5 ab 91 67 cb 1e c6 67 c0\n' +
        '             :     a4 92 0d f8 08 1c 4c 30 d8 2a a6 d9 40 32 1d dc\n' +
        '             :     c3 70 21 89 ad 98 ad df be 7f f9 98 b5 81 5e 0a\n' +
        '             :     de b6 e5 66 b9 aa eb ef e4 4b 43 0a 22 c9 2e 25\n' +
        '             :     51 00 e0 84 92 b1 dd 01 c8 24 82 6d 23 d1 3d f5\n' +
        '             :     cf d8 1b 6f 17 6a 6b 01 96 10 7f e3 e0 50 d2 99\n' +
        '  954 02  129:    INTEGER\n' +
        '             :     00 c6 cf 71 bf 27 5a 29 85 ff 6d 44 6b 17 d6 98\n' +
        '             :     73 af df eb 6c d6 c5 c3 26 94 aa 9d 6a c5 d3 61\n' +
        '             :     c6 66 43 82 f4 a7 9b 65 ba 66 d5 c7 be 46 b3 12\n' +
        '             :     d6 46 de 54 e2 c6 b8 e3 56 60 f4 8a d3 b7 ad b7\n' +
        '             :     e0 e3 96 b6 c1 ac 8f 04 00 6f e0 35 39 af 6c a1\n' +
        '             :     b4 ee e5 0e 13 20 c5 52 d4 e9 0d 52 af 5f c6 3f\n' +
        '             :     48 25 f8 cf b4 c0 9b b6 e4 2d 1a 98 de 6f 85 de\n' +
        '             :     91 0f 2b 6b b9 de 01 a3 9b 92 cb 40 83 33 fb 1b\n' +
        '             :     6b\n' +
        ' 1086 02  128:    INTEGER\n' +
        '             :     27 be e3 e1 0c ed fe 09 90 be cb de 0f d4 06 d8\n' +
        '             :     e5 a6 14 07 32 c6 37 af 51 47 2a 04 92 ad f1 4d\n' +
        '             :     53 5f 63 d8 dd 55 74 b0 77 66 b6 f5 0a d0 88 03\n' +
        '             :     ce 56 3b 01 6b f8 8b f0 1c d1 79 b4 26 9e 8f 66\n' +
        '             :     20 b6 18 e4 99 87 d6 77 96 13 9d b5 c6 48 78 62\n' +
        '             :     45 50 79 43 60 ae 41 18 b2 19 42 f1 b4 9c 23 38\n' +
        '             :     51 f0 ae 20 a1 a0 d2 1a 29 57 45 b1 12 8b bc aa\n' +
        '             :     0b b4 70 44 9e d4 3c 5b 0a d5 1a 6a ac 49 f2 dd\n' +
        '             :   }\n' +
        '             :  }\n' +
        '             : }';
let pkeyRsaJson = '{\n' +
    '    version: 0,\n' +
    '    privateKeyAlgorithm: {\n' +
    '        name: "RSASSA-PKCS1-v1_5",\n' +
    '        hash: {\n' +
    '            name: "SHA-256"\n' +
    '        },\n' +
    '        id: "rsaEncryption"\n' +
    '    },\n' +
    '    privateKey: [\n' +
    '        0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdc, 0x32, 0xa0, 0x68,\n' +
    '        0x51, 0x5d, 0x99, 0x8a, 0xa8, 0x5b, 0xa4, 0x6a, 0xf4, 0x0d, 0xf7, 0x26, 0x7a, 0x8f, 0xc1, 0xd8,\n' +
    '        0xda, 0x40, 0x17, 0x8d, 0xe3, 0x4f, 0x37, 0x93, 0x0a, 0x23, 0x42, 0x72, 0x8e, 0xfc, 0x5a, 0xf3,\n' +
    '        0x95, 0x45, 0x85, 0x36, 0xd8, 0x5f, 0x45, 0xee, 0xbf, 0x95, 0xf8, 0x39, 0xc0, 0x2c, 0xf2, 0x7a,\n' +
    '        0x00, 0xf8, 0x71, 0x69, 0x2e, 0xf7, 0xbb, 0xc2, 0xe7, 0x41, 0xef, 0xa0, 0xa6, 0x74, 0x5e, 0x4d,\n' +
    '        0x75, 0xc6, 0x54, 0x6f, 0x0a, 0x64, 0x58, 0x10, 0x50, 0xec, 0xa0, 0xe2, 0x31, 0x8c, 0xc7, 0xf6,\n' +
    '        0x3d, 0x46, 0x34, 0xd9, 0x13, 0x96, 0xd0, 0x81, 0x64, 0xa9, 0xcd, 0xfd, 0xc1, 0xcf, 0xe7, 0xa1,\n' +
    '        0x8b, 0xb9, 0x51, 0x8e, 0x07, 0x3c, 0x3a, 0x0e, 0x9e, 0xb0, 0x05, 0x04, 0x9e, 0xff, 0x4e, 0xd2,\n' +
    '        0x54, 0x1a, 0x77, 0x4e, 0xc9, 0x2e, 0x22, 0x5e, 0x95, 0x17, 0xa5, 0xc1, 0xe1, 0x71, 0xbc, 0x99,\n' +
    '        0x87, 0xde, 0xa3, 0x58, 0x06, 0x4d, 0x4d, 0xf2, 0xb0, 0xa2, 0x20, 0x88, 0x6b, 0x5b, 0x24, 0x34,\n' +
    '        0xc3, 0xb6, 0xac, 0x6a, 0xac, 0xa9, 0xc9, 0xdb, 0xd6, 0x57, 0x35, 0x12, 0x19, 0x13, 0xe8, 0x3c,\n' +
    '        0xf8, 0xf7, 0xa1, 0x98, 0xed, 0x83, 0x80, 0x01, 0x95, 0x85, 0xcb, 0x63, 0xfc, 0xbd, 0x17, 0xb0,\n' +
    '        0x72, 0x0d, 0xe4, 0xa4, 0xa4, 0x0d, 0xbd, 0xe7, 0x74, 0xa3, 0x99, 0xdb, 0x76, 0x25, 0x1f, 0xae,\n' +
    '        0xf2, 0xb4, 0xa5, 0xff, 0x95, 0x89, 0x4d, 0x0a, 0x7b, 0x2b, 0x1c, 0x3e, 0x67, 0x74, 0x18, 0x22,\n' +
    '        0x7f, 0xf0, 0x8e, 0xed, 0x81, 0x98, 0x5e, 0x64, 0x65, 0x96, 0x06, 0xf7, 0x10, 0xde, 0xf7, 0xdb,\n' +
    '        0xd7, 0x20, 0xc3, 0x0d, 0x41, 0x1d, 0x22, 0x05, 0x04, 0x2c, 0xb6, 0x73, 0x5a, 0xe1, 0xd1, 0x5a,\n' +
    '        0x23, 0x6e, 0x14, 0x91, 0xec, 0x09, 0xe8, 0xc4, 0xb9, 0x66, 0x26, 0x39, 0x02, 0x03, 0x01, 0x00,\n' +
    '        0x01, 0x02, 0x82, 0x01, 0x00, 0x13, 0xf5, 0x7c, 0x22, 0xad, 0xd5, 0x5d, 0x18, 0x7b, 0x60, 0x2b,\n' +
    '        0x21, 0x62, 0xa9, 0x18, 0x10, 0xe3, 0x25, 0x15, 0x53, 0x5c, 0x47, 0xae, 0x45, 0x8c, 0x7d, 0x5e,\n' +
    '        0xb2, 0x88, 0xf0, 0x5f, 0x3d, 0x2b, 0xb1, 0x66, 0x11, 0x14, 0x23, 0xae, 0xb5, 0x24, 0xf1, 0xa5,\n' +
    '        0xd0, 0xc3, 0xde, 0xdf, 0xc1, 0x64, 0x50, 0xee, 0xa8, 0x43, 0xb4, 0x41, 0x46, 0x0b, 0xc8, 0x25,\n' +
    '        0x65, 0xbf, 0x8e, 0x73, 0x73, 0xa2, 0xad, 0x83, 0x95, 0x63, 0xd5, 0x2b, 0xf6, 0xbb, 0x56, 0x13,\n' +
    '        0x16, 0xba, 0x2f, 0x13, 0x4f, 0x78, 0x0c, 0x4f, 0x07, 0xb1, 0x25, 0x79, 0x9e, 0xd4, 0xd9, 0x63,\n' +
    '        0xb6, 0xdc, 0x1d, 0x4e, 0xc5, 0x99, 0xd9, 0x5d, 0x76, 0x80, 0x1d, 0x61, 0x18, 0xb8, 0x41, 0x2b,\n' +
    '        0x9b, 0x58, 0x4e, 0x3e, 0x20, 0xdd, 0x6f, 0x3e, 0x2c, 0x19, 0xb6, 0xcd, 0xbf, 0xaa, 0x19, 0x46,\n' +
    '        0x16, 0x3f, 0xfa, 0x05, 0x15, 0x1d, 0xaa, 0x2b, 0x0f, 0xad, 0x33, 0xff, 0x59, 0x58, 0xf6, 0x24,\n' +
    '        0x8d, 0x00, 0x25, 0x64, 0x75, 0x80, 0x32, 0xbd, 0x75, 0xe8, 0x13, 0xba, 0xa2, 0xcf, 0xff, 0x99,\n' +
    '        0xc6, 0x77, 0x2d, 0x1a, 0xee, 0x41, 0x38, 0x03, 0xf0, 0x63, 0x41, 0x7f, 0x66, 0x9f, 0xec, 0x0f,\n' +
    '        0x3f, 0x8f, 0x9b, 0xc5, 0x14, 0x07, 0x76, 0x9f, 0x51, 0x42, 0x04, 0x9d, 0x4c, 0xc8, 0xb4, 0x95,\n' +
    '        0x8d, 0x8a, 0x5d, 0x2a, 0xd8, 0x01, 0xc7, 0xce, 0x43, 0x3a, 0xb3, 0x10, 0xfb, 0x2e, 0xf8, 0x55,\n' +
    '        0xae, 0x4b, 0x8f, 0xf4, 0x47, 0x51, 0x2a, 0xee, 0x1f, 0x8b, 0xfe, 0x41, 0xb2, 0x36, 0x39, 0x91,\n' +
    '        0xbc, 0xe8, 0x6f, 0x52, 0x62, 0x4f, 0x81, 0x0a, 0xa1, 0xe0, 0xca, 0x3e, 0x14, 0x5d, 0x0f, 0x6a,\n' +
    '        0x99, 0x98, 0xec, 0x9f, 0xa3, 0xb0, 0xae, 0xec, 0xec, 0xe8, 0x18, 0xcc, 0x67, 0x18, 0x9f, 0xae,\n' +
    '        0x17, 0xab, 0x45, 0xbd, 0x0d, 0x02, 0x81, 0x81, 0x00, 0xfe, 0x37, 0x20, 0x9f, 0xfa, 0xe9, 0x7d,\n' +
    '        0xa4, 0x41, 0x67, 0xb8, 0x69, 0x37, 0x81, 0x5c, 0x9d, 0x59, 0x82, 0x6e, 0x9d, 0xdb, 0xc4, 0xef,\n' +
    '        0x96, 0x7b, 0xb2, 0x6c, 0x63, 0xb1, 0x78, 0xd0, 0x5a, 0xf5, 0x45, 0x9d, 0x6e, 0x76, 0x98, 0x3c,\n' +
    '        0x68, 0xf8, 0xcd, 0x7f, 0x56, 0xfc, 0xf4, 0x0e, 0xf8, 0x6e, 0xd0, 0xcb, 0x6b, 0xce, 0x39, 0xfd,\n' +
    '        0x93, 0xb0, 0xb4, 0x7b, 0x76, 0x3c, 0xf8, 0x4f, 0x2f, 0x1f, 0x92, 0xe9, 0xde, 0x0f, 0x59, 0xec,\n' +
    '        0xc2, 0x50, 0x9e, 0xe3, 0x37, 0xea, 0x6c, 0xc7, 0xfe, 0x0a, 0xeb, 0xf6, 0xcd, 0x41, 0x46, 0x66,\n' +
    '        0xed, 0xc7, 0xe4, 0x60, 0x09, 0x94, 0xee, 0x95, 0x63, 0x9f, 0x3e, 0x97, 0x1a, 0xa6, 0x45, 0x42,\n' +
    '        0x93, 0xa0, 0x82, 0x38, 0x5c, 0x44, 0x71, 0xf3, 0xfd, 0x6e, 0xa4, 0x79, 0x00, 0x9b, 0xc2, 0x83,\n' +
    '        0x5a, 0x59, 0xd1, 0x92, 0x6d, 0xa9, 0x78, 0x85, 0xff, 0x02, 0x81, 0x81, 0x00, 0xdd, 0xbe, 0x5c,\n' +
    '        0xf9, 0xed, 0x55, 0x23, 0xbf, 0x81, 0xa1, 0xfd, 0x1e, 0x0c, 0xc1, 0x5a, 0xea, 0x05, 0x7f, 0x1d,\n' +
    '        0x5d, 0x17, 0x98, 0x36, 0x64, 0x3b, 0x34, 0x83, 0x3b, 0x74, 0x23, 0xab, 0xec, 0x02, 0xe2, 0x40,\n' +
    '        0xbb, 0xd7, 0x34, 0x0e, 0x67, 0x13, 0x3c, 0x68, 0xc5, 0xa6, 0xce, 0x20, 0x3c, 0xc2, 0x24, 0x07,\n' +
    '        0x8c, 0xff, 0x2a, 0x98, 0xb3, 0xb1, 0x39, 0x87, 0xc3, 0x42, 0x8e, 0x59, 0xfa, 0x96, 0x28, 0xb6,\n' +
    '        0x14, 0x88, 0xed, 0x88, 0xb7, 0xbb, 0xcb, 0x06, 0xbf, 0x89, 0x1a, 0xd8, 0xd7, 0xfe, 0x8b, 0x76,\n' +
    '        0xf8, 0xab, 0xd5, 0x56, 0x30, 0xf1, 0x8c, 0xb1, 0x3c, 0xa0, 0x68, 0x00, 0x3c, 0xab, 0x54, 0x86,\n' +
    '        0x43, 0xec, 0x6e, 0x6e, 0xf7, 0x79, 0x48, 0x75, 0x1d, 0x5e, 0xe9, 0xec, 0xb1, 0xde, 0x64, 0xd6,\n' +
    '        0x53, 0x05, 0x89, 0x0a, 0x72, 0xcf, 0xc5, 0x0a, 0x81, 0x94, 0xdc, 0x03, 0xc7, 0x02, 0x81, 0x80,\n' +
    '        0x32, 0x59, 0x50, 0xc8, 0xde, 0xb5, 0x28, 0x01, 0x44, 0x42, 0xfa, 0xaf, 0x3c, 0x23, 0x0e, 0xe8,\n' +
    '        0xcb, 0x35, 0x9e, 0x1a, 0xfd, 0xcf, 0xff, 0x73, 0xda, 0x83, 0xf8, 0x1b, 0xb6, 0xa6, 0xaa, 0xfd,\n' +
    '        0x98, 0xde, 0x74, 0xd3, 0xd0, 0x01, 0x4e, 0xd5, 0xab, 0x91, 0x67, 0xcb, 0x1e, 0xc6, 0x67, 0xc0,\n' +
    '        0xa4, 0x92, 0x0d, 0xf8, 0x08, 0x1c, 0x4c, 0x30, 0xd8, 0x2a, 0xa6, 0xd9, 0x40, 0x32, 0x1d, 0xdc,\n' +
    '        0xc3, 0x70, 0x21, 0x89, 0xad, 0x98, 0xad, 0xdf, 0xbe, 0x7f, 0xf9, 0x98, 0xb5, 0x81, 0x5e, 0x0a,\n' +
    '        0xde, 0xb6, 0xe5, 0x66, 0xb9, 0xaa, 0xeb, 0xef, 0xe4, 0x4b, 0x43, 0x0a, 0x22, 0xc9, 0x2e, 0x25,\n' +
    '        0x51, 0x00, 0xe0, 0x84, 0x92, 0xb1, 0xdd, 0x01, 0xc8, 0x24, 0x82, 0x6d, 0x23, 0xd1, 0x3d, 0xf5,\n' +
    '        0xcf, 0xd8, 0x1b, 0x6f, 0x17, 0x6a, 0x6b, 0x01, 0x96, 0x10, 0x7f, 0xe3, 0xe0, 0x50, 0xd2, 0x99,\n' +
    '        0x02, 0x81, 0x81, 0x00, 0xc6, 0xcf, 0x71, 0xbf, 0x27, 0x5a, 0x29, 0x85, 0xff, 0x6d, 0x44, 0x6b,\n' +
    '        0x17, 0xd6, 0x98, 0x73, 0xaf, 0xdf, 0xeb, 0x6c, 0xd6, 0xc5, 0xc3, 0x26, 0x94, 0xaa, 0x9d, 0x6a,\n' +
    '        0xc5, 0xd3, 0x61, 0xc6, 0x66, 0x43, 0x82, 0xf4, 0xa7, 0x9b, 0x65, 0xba, 0x66, 0xd5, 0xc7, 0xbe,\n' +
    '        0x46, 0xb3, 0x12, 0xd6, 0x46, 0xde, 0x54, 0xe2, 0xc6, 0xb8, 0xe3, 0x56, 0x60, 0xf4, 0x8a, 0xd3,\n' +
    '        0xb7, 0xad, 0xb7, 0xe0, 0xe3, 0x96, 0xb6, 0xc1, 0xac, 0x8f, 0x04, 0x00, 0x6f, 0xe0, 0x35, 0x39,\n' +
    '        0xaf, 0x6c, 0xa1, 0xb4, 0xee, 0xe5, 0x0e, 0x13, 0x20, 0xc5, 0x52, 0xd4, 0xe9, 0x0d, 0x52, 0xaf,\n' +
    '        0x5f, 0xc6, 0x3f, 0x48, 0x25, 0xf8, 0xcf, 0xb4, 0xc0, 0x9b, 0xb6, 0xe4, 0x2d, 0x1a, 0x98, 0xde,\n' +
    '        0x6f, 0x85, 0xde, 0x91, 0x0f, 0x2b, 0x6b, 0xb9, 0xde, 0x01, 0xa3, 0x9b, 0x92, 0xcb, 0x40, 0x83,\n' +
    '        0x33, 0xfb, 0x1b, 0x6b, 0x02, 0x81, 0x80, 0x27, 0xbe, 0xe3, 0xe1, 0x0c, 0xed, 0xfe, 0x09, 0x90,\n' +
    '        0xbe, 0xcb, 0xde, 0x0f, 0xd4, 0x06, 0xd8, 0xe5, 0xa6, 0x14, 0x07, 0x32, 0xc6, 0x37, 0xaf, 0x51,\n' +
    '        0x47, 0x2a, 0x04, 0x92, 0xad, 0xf1, 0x4d, 0x53, 0x5f, 0x63, 0xd8, 0xdd, 0x55, 0x74, 0xb0, 0x77,\n' +
    '        0x66, 0xb6, 0xf5, 0x0a, 0xd0, 0x88, 0x03, 0xce, 0x56, 0x3b, 0x01, 0x6b, 0xf8, 0x8b, 0xf0, 0x1c,\n' +
    '        0xd1, 0x79, 0xb4, 0x26, 0x9e, 0x8f, 0x66, 0x20, 0xb6, 0x18, 0xe4, 0x99, 0x87, 0xd6, 0x77, 0x96,\n' +
    '        0x13, 0x9d, 0xb5, 0xc6, 0x48, 0x78, 0x62, 0x45, 0x50, 0x79, 0x43, 0x60, 0xae, 0x41, 0x18, 0xb2,\n' +
    '        0x19, 0x42, 0xf1, 0xb4, 0x9c, 0x23, 0x38, 0x51, 0xf0, 0xae, 0x20, 0xa1, 0xa0, 0xd2, 0x1a, 0x29,\n' +
    '        0x57, 0x45, 0xb1, 0x12, 0x8b, 0xbc, 0xaa, 0x0b, 0xb4, 0x70, 0x44, 0x9e, 0xd4, 0x3c, 0x5b, 0x0a,\n' +
    '        0xd5, 0x1a, 0x6a, 0xac, 0x49, 0xf2, 0xdd\n' +
    '    ]\n' +
    '}';

    it('should create an instance', () => {
        expect(new GostViewer()).toBeTruthy();
    });


    it('print cert asn1', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printASN1 = gostViewer.printASN1(certRsa);
        console.log('\n' + printASN1);
        let actual = printASN1.replace(/[ \n\t\r]/g, ''); // своего рода canonicalization
        let expected = certRsaAsn1.replace(/[ \n\t\r]/g, ''); // своего рода canonicalization
        expect(actual === expected).toBeTruthy();
    });

    it('print pkey asn1', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printASN1 = gostViewer.printASN1(pkeyRsa);
        console.log('\n' + printASN1);
        let actual = printASN1.replace(/[ \n\t\r]/g, ''); // своего рода canonicalization
        let expected = pkeyRsaAsn1.replace(/[ \n\t\r]/g, ''); // своего рода canonicalization
        expect(actual === expected).toBeTruthy();
    });


    it('print nameGost asn1', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printASN1 = gostViewer.printASN1('MCkWJ2xlLWQzYmI4MDIzLTliNmEtNGRjMC05ZGI5LTdmNmQwNTUxNmY5OA');
        console.log('\n' + printASN1);
        let actual = printASN1.replace(/[ \n\t\r]/g, ''); // своего рода canonicalization
        let expected = ('    0 30   41: SEQUENCE {\n' +
            '    2 16   39:  IA5String "le-d3bb8023-9b6a-4dc0-9db9-7f6d05516f98"\n' +
            '             : }').replace(/[ \n\t\r]/g, ''); // своего рода canonicalization
        expect(actual === expected).toBeTruthy();
    });

    it('print cert json', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printSyntax = gostViewer.printSyntax(certRsa, undefined);
        console.log('\n' + printSyntax);
        expect(new GostViewer()).toBeTruthy();
    });



    it('print pkey RSA json', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printSyntax = gostViewer.printSyntax(pkeyRsa, Syntax.PrivateKeyInfo);

        console.log('\n' + printSyntax);

        expect(isSimilar(printSyntax, pkeyRsaJson)).toBeTruthy();
    });

    it('test1', () => {
        let gostViewer: GostViewer = new GostViewer();

        let encodedData: Uint8Array = new Uint8Array(Base64.decode(certRsa));
        let el2: BERElement = new BERElement();
        el2.fromBytes(encodedData);

        console.log('\n');
        expect(new GostViewer()).toBeTruthy();
    });

    it('print nameGost json', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printSyntax = gostViewer.printSyntax('MCkWJ2xlLWQzYmI4MDIzLTliNmEtNGRjMC05ZGI5LTdmNmQwNTUxNmY5OA', Syntax['']);
        console.log('\n' + printSyntax);
        expect(new GostViewer()).toBeTruthy();
    });


    it('print nameGost json syntax', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printSyntax = gostViewer.printSyntax('MCkWJ2xlLWQzYmI4MDIzLTliNmEtNGRjMC05ZGI5LTdmNmQwNTUxNmY5OA', 'GostKeyContainerName');
        console.log('\n' + printSyntax);
        let actual = printSyntax.replace(/[ \n\t\r]/g, ''); // своего рода canonicalization
        let expected = ('{\n' + '    containerName: "le-d3bb8023-9b6a-4dc0-9db9-7f6d05516f98"\n' + '}').replace(/[ \n\t\r]/g, ''); // своего рода canonicalization
        expect(actual === expected).toBeTruthy();
    });
});


function isSimilar(s1: string, s2: string): boolean {
    return (s1.replace(/[ \n\t\r]/g, '')) ===
        (s2.replace(/[ \n\t\r]/g, '')); // своего рода canonicalization

}
