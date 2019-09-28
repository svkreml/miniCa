import {Component, OnInit} from '@angular/core';
import {Alg} from '../dto/algs.enum';


import {CertDto} from '../dto/cert-dto';
import {
    AlgorithmIdentifier,
    AttributeTypeAndValue, AuthorityKeyIdentifier,
    Certificate,
    CertificateSerialNumber,
    Extension,
    Extensions,
    Name,
    RDNSequence,
    RelativeDistinguishedName,
    SubjectKeyIdentifier,
    SubjectPublicKeyInfo,
    TBSCertificate,
    UniqueIdentifier,
    Validity,
    Version
} from 'x509-ts';
import {ValidateCertificateComponent} from '../validate-certificate/validate-certificate.component';
import {CryptoModule} from '../crypto-module';
import {DerFunctions} from '../gost-crypto/gost-asn1/DerFunctions';
import {Base64, Hex} from '../gost-crypto/gost-coding/gost-coding';
import {BitUtils, PemConstant} from '../svkreml-utils/Utils';
import {OidInfo, OidMapper} from '../svkreml-utils/oid-mapper';
import {ObjectIdentifier} from 'asn1-ts';

@Component({
    selector: 'app-generate-certificate',
    templateUrl: './generate-certificate.component.html',
    styleUrls: ['./generate-certificate.component.css']
})


export class GenerateCertificateComponent implements OnInit {
    versions = [Version.v3, Version.v2, Version.v1];

    algorithms: Alg[] = [];


    // model = new CertReqDto();
    output: CertDto = new CertDto();
    certModel: CertModel = new CertModel();

    /*    name: { oidInfo: OidInfo, value: string }[] = [];
        exts: Extension[] = [];*/


    constructor() {

    }

    async  getSubjectKeyIdentifier(publicKeyInfo: SubjectPublicKeyInfo): Promise<Extension> {
        const hash: ArrayBuffer = await crypto.subtle.digest('SHA-1', BitUtils.fromBooleanArray(publicKeyInfo.subjectPublicKey));
        let subjectKeyIdentifier: SubjectKeyIdentifier = new Uint8Array(hash);
        return new Extension(
            new ObjectIdentifier([2, 5, 29, 14]),
            undefined,
            DerFunctions.createOctetString(subjectKeyIdentifier).toBytes()
        );
    }

    async  getAuthorityKeyIdentifier(publicKeyInfo: SubjectPublicKeyInfo): Promise<Extension> {
        const hash: ArrayBuffer = await crypto.subtle.digest('SHA-1', BitUtils.fromBooleanArray(publicKeyInfo.subjectPublicKey));
        let authorityKeyIdentifier: AuthorityKeyIdentifier = new AuthorityKeyIdentifier(new Uint8Array(hash), undefined, undefined);
        return new Extension(
            new ObjectIdentifier([2, 5, 29, 35]),
            undefined,
            authorityKeyIdentifier.toBytes()
        );
    }


    async onSubmit() {

        try {

            let keyPair: CryptoKeyPair = await CryptoModule.gCrypto.subtle.generateKey(
                this.certModel.algorithm.subtleParams,
                true,
                [
                    'sign',
                    'verify',
                ]
            );

            let ver: Version = this.certModel.version;
            let serialNumber: CertificateSerialNumber = new Uint8Array(Hex.decode(this.certModel.serialNumber));

            let subjectSignatureAlgorithmIdentifier: AlgorithmIdentifier = this.certModel.algorithm.signatureOid;

            let rdns: RelativeDistinguishedName[] = [];
            this.certModel.subject.forEach((name: { oidInfo: OidInfo; value: string }) => {
                try {
                    if (!name.value) {
                        return;
                    } // if empty do not do anything
                    const atal: AttributeTypeAndValue = new AttributeTypeAndValue(
                        name.oidInfo.oid,
                        DerFunctions.createByTag(name.value, name.oidInfo.tag),
                    );
                    const rdn: RelativeDistinguishedName = new RelativeDistinguishedName([atal]);
                    rdns.push(rdn);
                } catch (e) {
                    throw new Error('in ' + name.oidInfo.name + '\n' + e);
                }
            });

            let issuer: Name = new RDNSequence(rdns.reverse()); // reverse for the right order as in OidMapper

            let validity: Validity = new Validity(this.certModel.validity.notBefore, this.certModel.validity.notAfter);

            let subject: Name = issuer;


            const wrapped: ArrayBuffer = await CryptoModule.gCrypto.subtle.exportKey(
                'spki',
                keyPair.publicKey,
            );

            // let extensions: Extensions = this.getExtensions();

            let subjectPublicKeyInfo: SubjectPublicKeyInfo = SubjectPublicKeyInfo.fromBytes(new Uint8Array(wrapped));
            let extensions: Extensions = [];


            extensions.push(await this.getSubjectKeyIdentifier(subjectPublicKeyInfo));
            extensions.push(await this.getAuthorityKeyIdentifier(subjectPublicKeyInfo));



            let issuerUniqueID: UniqueIdentifier; // BitUtils.toBooleanArray(hash);
            let subjectUniqueID: UniqueIdentifier; // BitUtils.toBooleanArray(hash);
            // return extensions;


            let tbsCertificate: TBSCertificate = new TBSCertificate(
                ver,
                serialNumber,
                subjectSignatureAlgorithmIdentifier,
                issuer,
                validity,
                subject,
                subjectPublicKeyInfo,
                issuerUniqueID,
                subjectUniqueID,
                extensions
            );

            let certificate: Certificate = await this.signCertificate(tbsCertificate, keyPair);

            this.output.certificate = PemConstant.wrapCertificate(Base64.encode(certificate.toBytes()));

            const privateKey: ArrayBuffer = await CryptoModule.gCrypto.subtle.exportKey(
                'pkcs8',
                keyPair.privateKey,
            );

            this.output.privateKey = PemConstant.wrapPrivateKey(Base64.encode(privateKey));


            let result = await ValidateCertificateComponent.validateCert(this.output.certificate);
            if (!result.isValid) {
                alert('Созданный сертификат не валиден');
            }
        } catch (e) {
            alert(e);
            console.error(e);
        }
    }

    async signCertificate(tbsCertificate: TBSCertificate, issuerKeyPair: CryptoKeyPair): Promise<Certificate> {
        let signAlg: any = issuerKeyPair.privateKey.algorithm.name;
        if (issuerKeyPair.publicKey.algorithm.name === 'ECDSA') {
            // @ts-ignore
            if (issuerKeyPair.publicKey.algorithm.namedCurve === 'P-256') {
                signAlg = {
                    name: 'ECDSA',
                    hash: {name: 'SHA-256'},
                };
            }
            // @ts-ignore
            if (issuerKeyPair.publicKey.algorithm.namedCurve === 'P-384') {
                signAlg = {
                    name: 'ECDSA',
                    hash: {name: 'SHA-384'},
                };
            }
            // @ts-ignore
            if (issuerKeyPair.publicKey.algorithm.namedCurve === 'P-521') {
                signAlg = {
                    name: 'ECDSA',
                    hash: {name: 'SHA-512'},
                };
            }
        }

        let signature = await CryptoModule.gCrypto.subtle.sign(
            signAlg,
            issuerKeyPair.privateKey,
            tbsCertificate.toBytes()
        );

        let signatureAlgorithm: AlgorithmIdentifier = Alg.findAlgBySubtleParams(issuerKeyPair.privateKey.algorithm).signatureOid;
        let signatureValue: boolean[] = BitUtils.toBooleanArray(signature);
        console.log(Hex.encode(signature));
        console.log(Base64.encode(signature));
        return new Certificate(tbsCertificate, signatureAlgorithm, signatureValue);
    }

    ngOnInit(): void {
        Alg.algs.forEach((v: Alg, k: string) => {
            this.algorithms.push(v);
        });

        for (let oidM in OidMapper) {
            this.certModel.subject.push({oidInfo: OidMapper[oidM], value: 'vvvvvvvvv'});
        }
        this.certModel.serialNumber = (Math.random() * 10000000000000000000).toString(16);
        this.certModel.validity = new ValidityDto(new Date(), new Date(new Date().getFullYear() + 5, 1, 1));
        this.certModel.version = Version.v3;
        this.certModel.algorithm = this.algorithms[0];
    }

    setAlgorithm(alg: string) {
        this.certModel.algorithm = Alg.algs.get(alg);
    }

    private parseDate($event: string): Date {
        return new Date(Date.parse($event));
    }

    private async getExtensions() {

    }
}

export class CertModel {
    serialNumber: string;
    version: Version;
    algorithm: Alg;
    subject: { oidInfo: OidInfo, value: string }[] = [];
    exts: ExtensionModel[] = [];
    validity: ValidityDto;
}

export class ExtensionModel {
    oid: string;
    isCritical: boolean;
    data: any;
}

export class ValidityDto {
    notBefore: Date;
    notAfter: Date;

    constructor(notBefore: Date, notAfter: Date) {
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }
}




