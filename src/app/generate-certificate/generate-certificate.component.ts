import {Component, OnInit} from '@angular/core';
import {CertReqDto} from '../dto/cert-req-dto';
import {Alg} from '../dto/algs.enum';


import {CertDto} from '../dto/cert-dto';
import {
    AlgorithmIdentifier,
    Certificate,
    CertificateSerialNumber,
    SubjectPublicKeyInfo,
    TBSCertificate,
    Validity,
    Version
} from '../x509-ts-master/source/AuthenticationFramework';
import {DERElement, ObjectIdentifier} from 'asn1-ts';
import {
    AttributeTypeAndValue,
    Name,
    RDNSequence,
    RelativeDistinguishedName
} from '../x509-ts-master/source/InformationFramework';
import {UniqueIdentifier} from '../x509-ts-master/source/SelectedAttributeTypes/Version8';
import Extensions from '../x509-ts-master/source/AuthenticationFramework/Extensions';
import {ValidateCertificateComponent} from '../validate-certificate/validate-certificate.component';
import {CryptoModule} from '../crypto-module';
import {DerFunctions} from '../gost-crypto/gost-asn1/DerFunctions';
import {Base64} from '../gost-crypto/gost-coding/gost-coding';

@Component({
    selector: 'app-generate-certificate',
    templateUrl: './generate-certificate.component.html',
    styleUrls: ['./generate-certificate.component.css']
})
export class GenerateCertificateComponent implements OnInit {


    algs: Alg[] = Alg.getAlgs();
    model = new CertReqDto();
    output: CertDto = new CertDto();

    constructor() {
    }

    static toBitString(input: ArrayBuffer): boolean[] {
        let inputBytes = new Uint8Array(input);
        let output: boolean[] = [];

        for (let i = 0; i < inputBytes.byteLength; i++) {
            let b = inputBytes[i].toString(2);
            while (b.length < 8)
                b = '0' + b;
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

    async onSubmit() {

        let keyPair: CryptoKeyPair = await CryptoModule.gCrypto.subtle.generateKey(
            {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            [
                'sign',
                'verify',
            ]
        );

        let ver: Version = Version.v1;
        let serialNumber: CertificateSerialNumber = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
        let signatureAlgorithmIdentifier: AlgorithmIdentifier = new AlgorithmIdentifier(
            new ObjectIdentifier([1, 2, 840, 113549, 1, 1, 11]),
            new DERElement(),
        );


        let cn: AttributeTypeAndValue = new AttributeTypeAndValue(
            new ObjectIdentifier([2, 5, 4, 3]),
            DerFunctions.createUTF8String('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
        );
        let c: AttributeTypeAndValue = new AttributeTypeAndValue(
            new ObjectIdentifier([2, 5, 4, 6]),
            DerFunctions.createUTF8String('RU'),
        );
        let cnR: RelativeDistinguishedName = new RelativeDistinguishedName([cn]);
        let cR: RelativeDistinguishedName = new RelativeDistinguishedName([c]);
        let issuer: Name = new RDNSequence([cnR, cR]);


        let validity: Validity = new Validity(new Date(), new Date(2025, 12, 12));

        let subject: Name = issuer;


        const wrapped: ArrayBuffer = await CryptoModule.gCrypto.subtle.exportKey(
            'spki',
            keyPair.publicKey,
        );

        //  let subjectPublicKeyInfoElement: DERElement = new DERElement();
        //  subjectPublicKeyInfoElement.fromBytes(new Uint8Array(wrapped));
        let subjectPublicKeyInfo: SubjectPublicKeyInfo = SubjectPublicKeyInfo.fromBytes(new Uint8Array(wrapped));
        // new SubjectPublicKeyInfo(
        //     new AlgorithmIdentifier(
        //         new ObjectIdentifier([1, 3, 4, 6]),
        //         new DERElement(),
        //     ),
        //     this.toBitString(wrapped),
        // );

        let issuerUniqueID: UniqueIdentifier;
        let subjectUniqueID: UniqueIdentifier;
        let extensions: Extensions;


        let tbsCertificate: TBSCertificate = new TBSCertificate(
            ver,
            serialNumber,
            signatureAlgorithmIdentifier,
            issuer,
            validity,
            subject,
            subjectPublicKeyInfo,
            issuerUniqueID,
            subjectUniqueID,
            extensions
        );


        let signature = await CryptoModule.gCrypto.subtle.sign(
            keyPair.privateKey.algorithm.name,
            keyPair.privateKey,
            tbsCertificate.toBytes()
        );

        let signatureAlgorithm: AlgorithmIdentifier = new AlgorithmIdentifier(
            new ObjectIdentifier([1, 2, 840, 113549, 1, 1, 11]),
            new DERElement(),
        );
        let signatureValue: boolean[] = GenerateCertificateComponent.toBitString(signature);


        let certificate: Certificate = new Certificate(tbsCertificate, signatureAlgorithm, signatureValue);
        this.output.certificate = Base64.encode(certificate.toBytes());


        let result: boolean = await ValidateCertificateComponent.validateCert(this.output.certificate);
        if (!result)
            alert('Созданный сертификат не валиден');

    }

    ngOnInit(): void {
    }

}
