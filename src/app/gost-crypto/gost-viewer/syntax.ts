export enum Syntax {
    '' = '',
    PrivateKeyInfo = 'PrivateKeyInfo',
    EncryptedPrivateKeyInfo = 'EncryptedPrivateKeyInfo',
    SubjectPublicKeyInfo = 'SubjectPublicKeyInfo',
    Certificate = 'Certificate',
    CertificationRequest = 'CertificationRequest',
    CertificateList = 'CertificateList',
    AttributeCertificate = 'AttributeCertificate',
    ContentInfo = 'ContentInfo',
    PFX = 'PFX',
    PKIData = 'PKIData',
    PKIResponse = 'PKIResponse'
}

// tslint:disable-next-line:no-namespace
export namespace Syntax {
    export function getDescr(syntax: Syntax): string {
        switch (syntax) {
            case Syntax.PrivateKeyInfo:
                return 'PKCS #8: Private-Key Information Syntax';
            case Syntax.EncryptedPrivateKeyInfo:
                return 'PKCS #8: Encrypted Private-Key Information Syntax';
            case Syntax.SubjectPublicKeyInfo:
                return 'X.509 Certificate SubjectPublicKeyInfo Syntax';
            case Syntax.Certificate:
                return 'X.509 Certificate Syntax';
            case Syntax.CertificationRequest:
                return 'PKCS #10: Certification Request Syntax';
            case Syntax.CertificateList:
                return 'X.509 Certificate Revocation List Syntax';
            case Syntax.AttributeCertificate:
                return 'Attribute Certificate Profile Syntax';
            case Syntax.ContentInfo:
                return 'PKCS #7: Cryptographic Message Syntax';
            case Syntax.PFX:
                return 'PKCS #12: Personal Information Exchange Syntax';
            case Syntax.PKIData:
                return 'Certificate Management (CMC) PKIData Syntax';
            case Syntax.PKIResponse:
                return 'Certificate Management (CMC) PKIResponse Syntax';
            case Syntax['']:
                return 'No Syntax';
            default:
                return 'Неизвестно';
        }
    }
}
