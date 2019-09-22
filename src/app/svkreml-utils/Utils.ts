import {AlgorithmIdentifier} from 'x509-ts';

export class Utils {
}

export class CryptoSubtleMapper {
    static oidToParam(algorithmIdentifier: AlgorithmIdentifier): string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams | AesKeyAlgorithm {
        switch (algorithmIdentifier.algorithm.toString()) {
            case '1.2.840.113549.1.1.11':
                return {
                    name: 'RSASSA-PKCS1-v1_5',
                    hash: 'SHA-256',
                } as RsaHashedImportParams;
            case '1.2.840.113549.1.1.5':
                return {
                    name: 'RSASSA-PKCS1-v1_5',
                    hash: 'SHA-1',
                } as RsaHashedImportParams;
            case '1.2.840.113549.1.1.12':
                return {
                    name: 'RSASSA-PKCS1-v1_5',
                    hash: 'SHA-384',
                } as RsaHashedImportParams;
            case '1.2.840.113549.1.1.13':
                return {
                    name: 'RSASSA-PKCS1-v1_5',
                    hash: 'SHA-512',
                } as RsaHashedImportParams;
            case '1.2.840.10045.4.3.2':
                return {
                    name: 'ECDSA',
                    namedCurve: 'P-256',
                } as EcKeyImportParams;
            case '1.2.840.10045.4.3.3':
                return {
                    name: 'ECDSA',
                    namedCurve: 'P-384',
                } as EcKeyImportParams;
            case '1.2.840.10045.4.3.4':
                return {
                    name: 'ECDSA',
                    namedCurve: 'P-521',
                } as EcKeyImportParams;
            case '1.2.840.113549.1.1.2': // MD2
            case '1.2.840.113549.1.1.3': // MD4
            case '1.2.840.113549.1.1.4': // MD5
                alert('Устаревший алгоритм, браузер не хочет его поддерживать: ' + algorithmIdentifier.algorithm.toString());
                throw new Error('Устаревший алгоритм, браузер не хочет его поддерживать: ' + algorithmIdentifier.algorithm.toString());
            default:
                alert('неизвестный алгоритм: ' + algorithmIdentifier.algorithm.toString());
                throw new Error('неизвестный алгоритм: ' + algorithmIdentifier.algorithm.toString());
        }
    }
}


export class BitUtils {
    static fromBooleanArray(input: boolean[]): ArrayBuffer {
        let outputBytes = new Uint8Array(input.length / 8);
        for (let i = 0; i < outputBytes.byteLength; i++) {
            let b = 0;
            input[8 * i + 0] ? b |= 0b10000000 : '';
            input[8 * i + 1] ? b |= 0b01000000 : '';
            input[8 * i + 2] ? b |= 0b00100000 : '';
            input[8 * i + 3] ? b |= 0b00010000 : '';
            input[8 * i + 4] ? b |= 0b00001000 : '';
            input[8 * i + 5] ? b |= 0b00000100 : '';
            input[8 * i + 6] ? b |= 0b00000010 : '';
            input[8 * i + 7] ? b |= 0b00000001 : '';
            outputBytes[i] = b;
        }
        return outputBytes;
    }

    static toBooleanArray(input: ArrayBuffer): boolean[] {
        let inputBytes = new Uint8Array(input);
        let output: boolean[] = [];
        for (let i = 0; i < inputBytes.byteLength; i++) {
            let b = inputBytes[i].toString(2);
            while (b.length < 8) {
                b = '0' + b;
            }
            output.push(
                b.charAt(0) === '1',
                b.charAt(1) === '1',
                b.charAt(2) === '1',
                b.charAt(3) === '1',
                b.charAt(4) === '1',
                b.charAt(5) === '1',
                b.charAt(6) === '1',
                b.charAt(7) === '1'
            );
        }
        return output;
    }
}

export class PemConstant {
    static readonly pemPrivateKeyHeader = '-----BEGIN PRIVATE KEY-----';
    static readonly pemPrivateKeyFooter = '-----END PRIVATE KEY-----';
    static readonly pemCertificateHeader = '-----BEGIN CERTIFICATE-----';
    static readonly pemCertificateFooter = '-----END CERTIFICATE-----';
    static readonly pemPublicKeyHeader = '-----BEGIN PUBLIC KEY-----';
    static readonly pemPublicKeyFooter = '-----END PUBLIC KEY-----';

    public static wrapCertificate(cert: string): string {
        return PemConstant.pemCertificateHeader + '\n' + cert + '\n' + PemConstant.pemCertificateFooter;
    }

    public static unwrapCertificate(cert: string): string {
        return cert.replace(PemConstant.pemCertificateHeader, '').replace(PemConstant.pemCertificateFooter, '').trim();
    }

    public static wrapPrivateKey(privateKey: string): string {
        return PemConstant.pemPrivateKeyHeader + '\n' + privateKey + '\n' + PemConstant.pemPrivateKeyFooter;
    }

    public static unwrapPrivateKey(cert: string): string {
        return cert.replace(PemConstant.pemPrivateKeyHeader, '').replace(PemConstant.pemPrivateKeyFooter, '').trim();
    }
}
