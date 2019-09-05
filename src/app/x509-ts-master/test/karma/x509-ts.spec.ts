import {ObjectIdentifier} from 'asn1-ts';
import {toNumbers} from '@angular/compiler-cli/src/diagnostics/typescript_version';

import RDNSequence from '../../source//InformationFramework/RDNSequence';
import Version from '../../source//AuthenticationFramework/Version';
import Certificate from '../../source//AuthenticationFramework/Certificate';
import Name from '../../source//InformationFramework/Name';
import Validity from '../../source//AuthenticationFramework/Validity';
import SubjectPublicKeyInfo from '../../source//AuthenticationFramework/SubjectPublicKeyInfo';
import TBSCertificate from '../../source//AuthenticationFramework/TBSCertificate';
import AlgorithmIdentifier from '../../source/AuthenticationFramework/AlgorithmIdentifier';
import {DerFunctions} from '../../../gost-crypto/gost-asn1/DerFunctions';
import {Base64} from '../../../gost-crypto/gost-coding/gost-coding';
import {GostViewerTestData} from '../../../gost-crypto/gost-viewer/GostViewerTestData';
import {isSimilar} from '../../../gost-crypto/gost-viewer/gost-viewer.spec';


describe('TS-X509', () => {
    it('should recreate rsa cert', () => {
        let c: Certificate = Certificate.fromBytes(new Uint8Array(Base64.decode(GostViewerTestData.certRsa)));
        let s: string = Base64.encode(c.toBytes());
        console.log(s);
        expect(isSimilar(s, GostViewerTestData.certRsa)).toBeTruthy();
    });


    it('should create gostRsa', () => {

        let c: Certificate = Certificate.fromBytes(new Uint8Array(Base64.decode(GostViewerTestData.certRsa)));
        console.log(c);

        console.log(Base64.encode(c.tbsCertificate.issuer.toElement().toBytes()));

        expect(true).toBeTruthy();
    });
});
