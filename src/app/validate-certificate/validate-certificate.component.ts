import {Component, OnInit} from '@angular/core';
import {Certificate, TBSCertificate, Validity} from 'x509-ts';
import {Base64} from '../gost-crypto/gost-coding/gost-coding';
import {CryptoModule} from '../crypto-module';
import {BitUtils, CryptoSubtleMapper, PemConstant} from '../svkreml-utils/Utils';


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
            CryptoSubtleMapper.oidToParam(certificate.signatureAlgorithm),
            true,
            ['verify']
        );

        isSignValid = await CryptoModule.gCrypto.subtle.verify(
            publicKey.algorithm.name,
            publicKey,
            BitUtils.fromBooleanArray(signatureValue),
            certificate.tbsCertificate.toBytes(),
        );
        return isSignValid;
    }

    static async validateCert(inputCert: string): Promise<ValidationResult> {
        let result: ValidationResult = new ValidationResult();
        let certificate: Certificate = Certificate.fromBytes(
            new Uint8Array(
                Base64.decode(
                    PemConstant.unwrapCertificate(inputCert)
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
