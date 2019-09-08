import {ASN1Construction, ASN1TagClass, ASN1UniversalType, DERElement, ObjectIdentifier} from 'asn1-ts';
import Certificate from '../../source/AuthenticationFramework/Certificate';
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

    it('should recreate gost cert', () => {
        let c: Certificate = Certificate.fromBytes(new Uint8Array(Base64.decode(GostViewerTestData.certGost)));
        let s: string = Base64.encode(c.toBytes());
        console.log(s);
        expect(isSimilar(s, GostViewerTestData.certGost)).toBeTruthy();
    });
    it('should recreate gost256 cert', () => {
        let c: Certificate = Certificate.fromBytes(new Uint8Array(Base64.decode(GostViewerTestData.certGost256)));
        let s: string = Base64.encode(c.toBytes());
        console.log(s);
        expect(isSimilar(s, GostViewerTestData.certGost256)).toBeTruthy();
    });

    it('should recreate issuer', () => {

        let c: Certificate = Certificate.fromBytes(new Uint8Array(Base64.decode(GostViewerTestData.certRsa)));
        console.log(c);

        console.log(Base64.encode(c.tbsCertificate.issuer.toElement().toBytes()));

        expect(Base64.encode(c.tbsCertificate.issuer.toElement().toBytes()).length > 40).toBeTruthy();
    });

    it('should recreate certGoogleECDSAP256', () => {
        let c: Certificate = Certificate.fromBytes(new Uint8Array(Base64.decode(GostViewerTestData.certRsa)));
        let s: string = Base64.encode(c.toBytes());
       // console.log('-------------------JSON --------------------------------------');
       // console.log(JSON.stringify(c, null, 2));
        console.log(s);
        expect(isSimilar(s, GostViewerTestData.certRsa)).toBeTruthy();
    });

    it('should create keyUsageOid', () => {


        let keyUsageOid: DERElement = DerFunctions.convertOid('2.5.29.15');
        console.log(Base64.encode(keyUsageOid.toBytes()));

        let extnID: ObjectIdentifier = new ObjectIdentifier([2, 5, 29, 15]);
        const extnIDElement: DERElement = new DERElement();
        extnIDElement.tagClass = ASN1TagClass.universal;
        extnIDElement.construction = ASN1Construction.primitive;
        extnIDElement.tagNumber = ASN1UniversalType.objectIdentifier;
        extnIDElement.objectIdentifier = extnID;
        console.log(Base64.encode(extnIDElement.toBytes()));

        expect(true).toBeTruthy();
    });

});
