import {GostViewer} from './gost-viewer';
import {Syntax} from './syntax';
import {Base64} from '../gost-coding/gost-coding';
import {GostViewerTestData} from './GostViewerTestData';
import {GostKeyContainerName} from '../gost-asn1/gost-asn1';
import {PrivateKeyInfo} from '../gost-asn1/private-keys-algs/private-key-info';

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

    it('print cert GOST json', () => {
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

        let arrayBuffer = GostViewer.asn1.PrivateKeyInfo.encode(privateKeyInfo);
        let encoded = Base64.encode(arrayBuffer);
        console.log(GostViewerTestData.pkeyGost2001);
        console.log(encoded);

        expect(isSimilar(GostViewerTestData.pkeyGost2001, encoded)).toBeTruthy();
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














});


function isSimilar(s1: string, s2: string): boolean {
    return (s1.replace(/[ \n\t\r]/g, '')) ===
        (s2.replace(/[ \n\t\r]/g, '')); // своего рода canonicalization

}
