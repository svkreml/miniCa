import {
    AlgorithmIdentifier,
    AttributeTypeAndValue,
    Certificate,
    RDNSequence,
    RelativeDistinguishedName,
    SubjectPublicKeyInfo,
    TBSCertificate,
    Validity,
    Version
} from 'x509-ts';
import {DERElement, ObjectIdentifier} from 'asn1-ts';
import {DerFunctions} from '../gost-asn1/DerFunctions';
import {toNumbers} from '@angular/compiler-cli/src/diagnostics/typescript_version';
import {BERtypes} from '../gost-asn1/structure/BERTypes';
import {Base64} from '../gost-coding/gost-coding';
import {Meta, Name} from '../gost-asn1/certificate/Certificate';


describe('GostSubtle', () => {
    it('should create an instance', () => {
        let subject: Map<string, Meta> = new Map<string, Meta>();
        let set = DerFunctions.createSet([DerFunctions.createSequence([DerFunctions.convertOid('2.4.6.2'), DerFunctions.createUTF8String('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')])]);
        set.construction = 1;
        subject.set('1.1.1', new Meta('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', BERtypes.UTF8String));
        subject.set('1.1.2', new Meta('123123123123123123123', BERtypes.NumericString));

        let name: Name = new Name(subject);
        let c: Certificate = new Certificate(
            new TBSCertificate(
                Version.v3,
                new Uint8Array([12, 12, 12, 12, 12, 12, 12]),
                new AlgorithmIdentifier(
                    new ObjectIdentifier(toNumbers('1.1.1.1.1.1.1.1')),
                    DerFunctions.createInteger(123)
                ),
              new RDNSequence(
                    [RelativeDistinguishedName.fromElement(set)]
                ),
                new Validity(new Date(), new Date()),
                RDNSequence.fromElement(name.toElement(name)),
                new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(
                        new ObjectIdentifier(toNumbers('1.4.4.4.4.4.4.4.4')),
                        DerFunctions.createInteger(456)
                    ),
                    []
                ),
                undefined,
                undefined,
                []
            ),
            new AlgorithmIdentifier(
                new ObjectIdentifier(toNumbers('1.5.5.5.5.5.5.5.5')),
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
});
