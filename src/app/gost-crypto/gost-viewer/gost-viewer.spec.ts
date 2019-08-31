import {GostViewer} from './gost-viewer';
import {Syntax} from './syntax';
import {BERElement} from 'asn1-ts';
import {Base64, GostCoding, PEM} from '../gost-coding/gost-coding';
import {BERtypes} from './BERTypes';
import {GostViewerTestData} from './GostViewerTestData';
import {GostKeyContainerName} from '../gost-asn1/gost-asn1';

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

    it('print pkey asn1', () => {
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
        let printSyntax = gostViewer.printSyntax(GostViewerTestData.certGost256, undefined);
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
});


function isSimilar(s1: string, s2: string): boolean {
    return (s1.replace(/[ \n\t\r]/g, '')) ===
        (s2.replace(/[ \n\t\r]/g, '')); // своего рода canonicalization

}
