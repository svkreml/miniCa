import {Component, OnInit} from '@angular/core';
import {Certificate, Validity} from '../x509-ts-master/source/AuthenticationFramework';
import {Base64} from '../gost-crypto/gost-coding/gost-coding';
import TBSCertificate from '../x509-ts-master/source/AuthenticationFramework/TBSCertificate';
import {CryptoModule} from '../crypto-module';
import AlgorithmIdentifier from '../x509-ts-master/source/AuthenticationFramework/AlgorithmIdentifier';


class V3ValidationResult {
}

class ValidationResult {
    isSignValid: boolean;
    isNotInCrl: boolean;
    isDateValid: boolean;
    v3Validation: V3ValidationResult;

    get isValid(): boolean {
        return this.isSignValid && this.isDateValid;
    }
}

@Component({
    selector: 'app-validate-certificate',
    templateUrl: './validate-certificate.component.html',
    styleUrls: ['./validate-certificate.component.css']
})
export class ValidateCertificateComponent implements OnInit {

    output: string;
    inputCert: string = '';

    constructor() {
    }

    static removeHeaderAndFooter(input: string): string {
        return input;
    }

    static fromBitString(input: boolean[]): ArrayBuffer {

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

    static algorithmToCryptoSubtleMapper(algorithmIdentifier: AlgorithmIdentifier): string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams | AesKeyAlgorithm {
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

    static validateCertDate(validity: Validity): boolean {
        const now: Date = new Date();
        return validity.notBefore < now && validity.notAfter > now;
    }

    static async validateCertSign(certificate: Certificate): Promise<boolean> { // TODO Если это не самоподписанный сертификат, то самое время найти всю цепочку, иначе ничего не выйдет
        let isSignValid;
        let signatureValue: boolean[] = certificate.signatureValue;
        let publicKey = await CryptoModule.gCrypto.subtle.importKey(
            'spki',
            certificate.tbsCertificate.subjectPublicKeyInfo.toBytes(),
            ValidateCertificateComponent.algorithmToCryptoSubtleMapper(certificate.signatureAlgorithm),
            true,
            ['verify']
        );

        isSignValid = await CryptoModule.gCrypto.subtle.verify(
            publicKey.algorithm.name,
            publicKey,
            ValidateCertificateComponent.fromBitString(signatureValue),
            certificate.tbsCertificate.toBytes(),
        );
        return isSignValid;
    }

    static async validateCert(inputCert: string): Promise<ValidationResult> {
        let result: ValidationResult = new ValidationResult();
        let certificate: Certificate = Certificate.fromBytes(
            new Uint8Array(
                Base64.decode(
                    ValidateCertificateComponent.removeHeaderAndFooter(inputCert)
                )
            )
        );

        let tbsCertificate: TBSCertificate = certificate.tbsCertificate;

        result.isDateValid = ValidateCertificateComponent.validateCertDate(tbsCertificate.validity);
        result.isSignValid = await ValidateCertificateComponent.validateCertSign(certificate);
        return result;
    }

    async onSubmit() {
        let inputCert = this.inputCert;
        let result: ValidationResult = await ValidateCertificateComponent.validateCert(inputCert);
        this.output = JSON.stringify(result);
    }

    ngOnInit(): void {
    }
}
