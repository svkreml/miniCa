import {GostViewer} from './gost-viewer';
import {Syntax} from './syntax';
import {Base64} from '../gost-coding/gost-coding';
import {GostViewerTestData} from './GostViewerTestData';
import {PrivateKeyInfo} from '../gost-asn1/private-keys-algs/private-key-info';
import {GostSecurity} from '../gost-security/gost-security';
import {GostKeyContainerName, GostPrivateKeys, GostPrivateMasks} from '../gost-asn1/cp/CP';
import {Meta, Name} from '../gost-asn1/certificate/Certificate';

describe('GostViewer', () => {


    it('should create an instance', () => {
        expect(new GostViewer()).toBeTruthy();
    });


    it('print cert RSA asn1', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printASN1 = gostViewer.printASN1(GostViewerTestData.certRsa);
        console.log('\n' + printASN1);
        expect(isSimilar(printASN1, GostViewerTestData.certRsaAsn1)).toBeTruthy();
    });

    it('print pkey RSA asn1', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printASN1 = gostViewer.printASN1(GostViewerTestData.pkeyRsa);
        console.log('\n' + printASN1);
        expect(isSimilar(printASN1, GostViewerTestData.pkeyRsaAsn1)).toBeTruthy();
    });

    it('print pkey RSA json', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printSyntax = gostViewer.printSyntax(GostViewerTestData.pkeyRsa, Syntax.PrivateKeyInfo);
        console.log('\n' + printSyntax);
        expect(isSimilar(printSyntax, GostViewerTestData.pkeyRsaJson)).toBeTruthy();
    });

    it('print cert GOST json Syntax.Certificate', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printSyntax = gostViewer.printSyntax(GostViewerTestData.certGost256, Syntax.Certificate);
        console.log('\n' + printSyntax);
        expect(isSimilar(GostViewerTestData.certGOST256Json, printSyntax)).toBeTruthy();
    });


    it('print nameGost asn1', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printASN1 = gostViewer.printASN1(GostViewerTestData.cryptoProName);
        console.log('\n' + printASN1);
        expect(isSimilar(printASN1, GostViewerTestData.cryptoProNameAsn1)).toBeTruthy();
    });

    it('print nameGost json Syntax[\'\']', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printSyntax = gostViewer.printSyntax(GostViewerTestData.cryptoProName, Syntax['']);
        console.log('\n' + printSyntax);
        expect(new GostViewer()).toBeTruthy();
    });


    it('print nameGost json Syntax.GostKeyContainerName', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printSyntax = gostViewer.printSyntax(GostViewerTestData.cryptoProName, 'GostKeyContainerName');
        console.log('\n' + printSyntax);
        expect(isSimilar(printSyntax, GostViewerTestData.cryptoProNameJson)).toBeTruthy();
    });


    it('print nameGost json Syntax.GostKeyContainerName recreate', () => {
        let gostKeyContainerName: GostKeyContainerName = GostViewer.asn1.GostKeyContainerName.decode(
            Base64.decode(GostViewerTestData.cryptoProName));

        let arrayBuffer = GostViewer.asn1.GostKeyContainerName.encode(gostKeyContainerName);
        let encoded = Base64.encode(arrayBuffer);
        console.log(GostViewerTestData.cryptoProName);
        console.log(encoded);

        expect(isSimilar(GostViewerTestData.cryptoProName, encoded)).toBeTruthy();
    });

    it('print pkey rsa json Syntax.PrivateKeyInfo recreate', () => {
        let privateKeyInfo: PrivateKeyInfo = GostViewer.asn1.PrivateKeyInfo.decode(
            Base64.decode(GostViewerTestData.pkeyRsa));

        let arrayBuffer = GostViewer.asn1.PrivateKeyInfo.encode(privateKeyInfo);
        let encoded = Base64.encode(arrayBuffer);
        console.log(GostViewerTestData.pkeyRsa);
        console.log(encoded);

        expect(isSimilar(GostViewerTestData.pkeyRsa, encoded)).toBeTruthy();
    });

    it('print pkey gost2001 json Syntax.PrivateKeyInfo recreate', () => {
        let privateKeyInfo: PrivateKeyInfo = GostViewer.asn1.PrivateKeyInfo.decode(
            Base64.decode(GostViewerTestData.pkeyGost2001));
        let recreatedPrivateKeyInfo = Base64.encode(GostViewer.asn1.PrivateKeyInfo.encode(privateKeyInfo));
        console.log(GostViewerTestData.pkeyGost2001);
        console.log(recreatedPrivateKeyInfo);

        expect(isSimilar(GostViewerTestData.pkeyGost2001, recreatedPrivateKeyInfo)).toBeTruthy();
    });

    it('print pkey gost2012 json Syntax.PrivateKeyInfo recreate', () => {
        let privateKeyInfo: PrivateKeyInfo = GostViewer.asn1.PrivateKeyInfo.decode(
            Base64.decode(GostViewerTestData.pkeyGost2012));
        let recreatedPrivateKeyInfo = Base64.encode(GostViewer.asn1.PrivateKeyInfo.encode(privateKeyInfo));
        console.log(GostViewerTestData.pkeyGost2012);
        console.log(recreatedPrivateKeyInfo);

        expect(isSimilar(GostViewerTestData.pkeyGost2012, recreatedPrivateKeyInfo)).toBeTruthy();
    });


    it('print pkey gost2012strong json Syntax.PrivateKeyInfo recreate', () => {
        let privateKeyInfo: PrivateKeyInfo = GostViewer.asn1.PrivateKeyInfo.decode(
            Base64.decode(GostViewerTestData.pkeyGost2012str));
        let recreatedPrivateKeyInfo = Base64.encode(GostViewer.asn1.PrivateKeyInfo.encode(privateKeyInfo));
        console.log(GostViewerTestData.pkeyGost2012str);
        console.log(recreatedPrivateKeyInfo);

        expect(isSimilar(GostViewerTestData.pkeyGost2012str, recreatedPrivateKeyInfo)).toBeTruthy();
    });


    it('print pkey gost2001 asn1', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printASN1 = gostViewer.printASN1(GostViewerTestData.pkeyGost2001);
        console.log('\n' + printASN1);
        expect(isSimilar(printASN1, GostViewerTestData.pkeyGost2001Asn1)).toBeTruthy();
    });

    it('print pkey gost2001 json', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printSyntax = gostViewer.printSyntax(GostViewerTestData.pkeyGost2001, Syntax.PrivateKeyInfo);
        console.log('\n' + printSyntax);
        expect(isSimilar(printSyntax, GostViewerTestData.pkeyGost2001Json)).toBeTruthy();
    });


    it('GostSecurity test', () => {
        let gostSecurity: GostSecurity = new GostSecurity();

        console.log(gostSecurity);
        expect(gostSecurity).toBeTruthy();
    });


    it('recreate Crypto pro 2001 primary', () => {
        let gostViewer: GostViewer = new GostViewer();
        let c = GostViewerTestData.cryptoProConteiner;
        /*
        header - container header @link GostASN1.GostKeyContainer</li>
        name - container name @link GostASN1.GostKeyContainerName</li>
        primary - private keys data @link GostASN1.GostPrivateKeys</li>
        masks - private key masks @link GostASN1.GostPrivateMasks</li>
        primary2 - reserve of private keys data @link GostASN1.GostPrivateKeys</li>
        masks2 - reserve of private key masks @link GostASN1.GostPrivateMasks</li>
        * */
       // let header = gostViewer.printSyntax(c.header, 'GostKeyContainer');
       // let name = gostViewer.printSyntax(c.name, 'GostKeyContainerName');
        {
            let primary = gostViewer.printSyntax(c.primary, 'GostPrivateKeys');
            let primary2 = gostViewer.printSyntax(c.primary2, 'GostPrivateKeys');
            console.log('\n' + primary);
            console.log('\n' + primary2);
        }
        let primary: GostPrivateKeys = GostViewer.asn1.GostPrivateKeys.decode(
            Base64.decode(c.primary));

        let recreatedPrimary: string = Base64.encode(GostViewer.asn1.GostPrivateKeys.encode(primary));
        console.log(c.primary);
        console.log(recreatedPrimary);



       // let masks = gostViewer.printSyntax(c.masks, 'GostPrivateMasks');
       // let masks2 = gostViewer.printSyntax(c.masks2, 'GostPrivateMasks');


        //  console.log('\n' + printSyntax);
        expect(isSimilar(c.primary, recreatedPrimary)).toBeTruthy();
    });

    it('recreate Crypto pro 2001 masks', () => {
        let gostViewer: GostViewer = new GostViewer();
        let c = GostViewerTestData.cryptoProConteiner;

        // let header = gostViewer.printSyntax(c.header, 'GostKeyContainer');
        {
            let masks = gostViewer.printSyntax(c.masks, 'GostPrivateMasks');
            let masks2 = gostViewer.printSyntax(c.masks2, 'GostPrivateMasks');
            console.log('\n' + masks);
            console.log('\n' + masks2);
        }
        let masks: GostPrivateMasks = GostViewer.asn1.GostPrivateMasks.decode(
            Base64.decode(c.masks));

        let recreatedMasks: string = Base64.encode(GostViewer.asn1.GostPrivateMasks.encode(masks));
        console.log(c.masks);
        console.log(recreatedMasks);



        // let masks = gostViewer.printSyntax(c.masks, 'GostPrivateMasks');
        // let masks2 = gostViewer.printSyntax(c.masks2, 'GostPrivateMasks');


        //  console.log('\n' + printSyntax);
        expect(isSimilar(c.masks, recreatedMasks)).toBeTruthy();
    });




    it('print create x500Name', () => {

        let subject: Map<string, Meta> = new Map<string, Meta>();

        subject.set('1.1.1', new Meta('123', 0x12));
        subject.set('1.1.2', new Meta('123', undefined));

        let name: Name = new Name(subject);
        let x500Name: string = Base64.encode(GostViewer.asn1.Name.encode(name));
        console.log('\n' + x500Name);
        expect(isSimilar(x500Name, 'MBoxCzAJBgIpARIDMTIzMQswCQYCKQIMAzEyMw==')).toBeTruthy();
    });

});


export function isSimilar(s1: string, s2: string): boolean {
    return (s1.replace(/[ \n\t\r]/g, '')) ===
        (s2.replace(/[ \n\t\r]/g, '')); // своего рода canonicalization

}
