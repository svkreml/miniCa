import {Component, OnInit} from '@angular/core';
import {Certificate} from '../x509-ts-master/source/AuthenticationFramework';
import {Base64} from '../gost-crypto/gost-coding/gost-coding';
import TBSCertificate from '../x509-ts-master/source/AuthenticationFramework/TBSCertificate';
import {CryptoModule} from '../crypto-module';

@Component({
    selector: 'app-validate-certificate',
    templateUrl: './validate-certificate.component.html',
    styleUrls: ['./validate-certificate.component.css']
})
export class ValidateCertificateComponent implements OnInit {

    output: string;
    inputCert: string =
        'MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\n' +
        'A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\n' +
        'Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\n' +
        'MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\n' +
        'A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n' +
        'hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\n' +
        'RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\n' +
        'gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\n' +
        'KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\n' +
        'QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\n' +
        'XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\n' +
        'DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\n' +
        'LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\n' +
        'RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\n' +
        'jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\n' +
        '6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\n' +
        'mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\n' +
        'Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\n' +
        'WD9f';

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

    async onSubmit() {
        let inputCert = this.inputCert;

        let result: boolean = await ValidateCertificateComponent.validateCert(inputCert);
        this.output = result ? 'valid' : 'invalid';
    }

    ngOnInit(): void {
    }

    static async validateCert(inputCert: string): Promise<boolean> {
        let certificate: Certificate = Certificate.fromBytes(
            new Uint8Array(
                Base64.decode(
                    ValidateCertificateComponent.removeHeaderAndFooter(inputCert)
                )
            )
        );

        let tbsCertificate: TBSCertificate = certificate.tbsCertificate;
        let signatureValue: boolean[] = certificate.signatureValue;
        let subjectPublicKeyInfo = certificate.tbsCertificate.subjectPublicKeyInfo;

        let publicKey = await CryptoModule.gCrypto.subtle.importKey(
            'spki',
            subjectPublicKeyInfo.toBytes(),
            {
                name: 'RSASSA-PKCS1-v1_5',
                //  modulusLength: 2048,
                //  publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256',
            },
            true,
            ['verify']
        );

        return CryptoModule.gCrypto.subtle.verify(
            'RSASSA-PKCS1-v1_5',
            publicKey,
            ValidateCertificateComponent.fromBitString(signatureValue),
            tbsCertificate.toBytes(),
        );
    }
}
