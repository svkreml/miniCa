import {ObjectIdentifier} from 'asn1-ts';
import {DerFunctions} from '../gost-asn1/DerFunctions';
import RDNSequence from '../../x509-ts-master/source/InformationFramework/RDNSequence';
import Version from '../../x509-ts-master/source/AuthenticationFramework/Version';
import Certificate from '../../x509-ts-master/source/AuthenticationFramework/Certificate';
import {Base64} from '../gost-coding/gost-coding';
import {GostViewerTestData} from '../gost-viewer/GostViewerTestData';
import Name from '../../x509-ts-master/source/InformationFramework/Name';
import Validity from '../../x509-ts-master/source/AuthenticationFramework/Validity';
import SubjectPublicKeyInfo from '../../x509-ts-master/source/AuthenticationFramework/SubjectPublicKeyInfo';
import TBSCertificate from '../../x509-ts-master/source/AuthenticationFramework/TBSCertificate';
import AlgorithmIdentifier from '../../x509-ts-master/source/AuthenticationFramework/AlgorithmIdentifier';


describe('GostSubtle', () => {
    it('should create an instance', () => {

        let c1: Certificate = Certificate.fromBytes(new Uint8Array(Base64.decode(GostViewerTestData.certRsa)));
      //  console.log(c);

        console.log(Base64.encode(c1.tbsCertificate.issuer.toElement().toBytes()));


        let c: Certificate = new Certificate(
            new TBSCertificate(
                Version.v3,
                new Uint8Array([12, 12, 12, 12, 12, 12, 12]),
                new AlgorithmIdentifier(
                    new ObjectIdentifier('1.1.1.1.1.1.1.1'.split('.').map(Number)),
                    DerFunctions.createInteger(123)
                ),
                RDNSequence.fromElement(c1.tbsCertificate.issuer.toElement()) as Name,
                new Validity(new Date(), new Date()),
                RDNSequence.fromElement(c1.tbsCertificate.issuer.toElement()) as Name,
                new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(
                        new ObjectIdentifier('1.4.4.4.4.4.4.4.4'.split('.').map(Number)),
                        DerFunctions.createInteger(456)
                    ),
                    []
                ),
                undefined,
                undefined,
                []
            ),
            new AlgorithmIdentifier(
                new ObjectIdentifier('1.5.5.5.5.5.5.5.5'.split('.').map(Number)),
                undefined
            ),
            [true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false, true, false]
        );

        let s: string = Base64.encode(
            c.toBytes()
        );
        console.log(s);


        expect(true).toBeTruthy();
    });


    it('should create Rsa', () => {

        let c: Certificate = Certificate.fromBytes(new Uint8Array(Base64.decode(GostViewerTestData.certRsa)));
        console.log(c);

        console.log(Base64.encode(c.tbsCertificate.issuer.toElement().toBytes()));

        expect(true).toBeTruthy();
    });
});
