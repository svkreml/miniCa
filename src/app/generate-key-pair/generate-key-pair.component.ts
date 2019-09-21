import {Component, OnInit} from '@angular/core';
import {Base64} from '../gost-crypto/gost-coding/gost-coding';
import {CryptoModule} from '../crypto-module';
import {PemConstant} from '../svkreml-utils/Utils';

@Component({
    selector: 'app-generate-key-pair',
    templateUrl: './generate-key-pair.component.html',
    styleUrls: ['./generate-key-pair.component.css']
})
export class GenerateKeyPairComponent implements OnInit {
    input: string;
    signature: string;
    verifyResult: string;


    keyPair: CryptoKeyPair;
    exportedKeyPair: string;

    constructor() {
    }

    ngOnInit() {
    }

    generateKeyPair() {
        console.log('Generate button clicked!');

        CryptoModule.gCrypto.subtle.generateKey(
            {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            [
                // 'encrypt',
                //  'decrypt',
                'sign',
                'verify',
                // 'deriveKey',
                // 'deriveBits',
                // 'wrapKey',
                // 'unwrapKey'
            ]
        ).then((keyPair: CryptoKeyPair) => {
            this.keyPair = keyPair;
            console.log('generated keyPair:');
            console.log('this.keyPair.publicKey:');
            console.log(this.keyPair.publicKey);
            console.log('this.keyPair.privateKey:');
            console.log(this.keyPair.privateKey);
        });

    }

    async verify() {
        this.verifyResult = 'calculating...';

        let result: boolean = await CryptoModule.gCrypto.subtle.verify(
            this.keyPair.publicKey.algorithm.name,
            this.keyPair.publicKey,
            Base64.decode(this.signature),
            this.encodeMessage(this.input),
        );
        this.verifyResult = result ? 'valid' : 'invalid';
    }

    sign() {
        CryptoModule.gCrypto.subtle.sign(
            this.keyPair.privateKey.algorithm.name,
            this.keyPair.privateKey,
            this.encodeMessage(this.input)
        ).then((r: ArrayBuffer) => {
                this.signature = Base64.encode(r);
            }
        );
    }

    encodeMessage(input: string): Uint8Array {
        let enc = new TextEncoder();
        return enc.encode(input);
    }

    decodeMessage(input: ArrayBuffer): string {
        let enc = new TextDecoder();
        return enc.decode(input);
    }

    async exportKeyPair() {
        this.exportedKeyPair = '';


        const publicKey: ArrayBuffer = await CryptoModule.gCrypto.subtle.exportKey(
            'spki',
            this.keyPair.publicKey,
        );

        this.exportedKeyPair += PemConstant.pemPublicKeyHeader + '\n';
        this.exportedKeyPair += Base64.encode(publicKey);
        this.exportedKeyPair += '\n' + PemConstant.pemPublicKeyFooter + '\n';


        const privateKey: ArrayBuffer = await CryptoModule.gCrypto.subtle.exportKey(
            'pkcs8',
            this.keyPair.privateKey,
        );
        this.exportedKeyPair += PemConstant.pemPrivateKeyHeader + '\n';
        this.exportedKeyPair += Base64.encode(privateKey);
        this.exportedKeyPair += '\n' + PemConstant.pemPrivateKeyFooter;
    }


    async importKeyPair() {
        // this.keyPair = new CryptoKeyPair();


        this.keyPair.publicKey = await CryptoModule.gCrypto.subtle.importKey(
            'spki',
            Base64.decode(this.exportedKeyPair.substring(this.exportedKeyPair.indexOf(PemConstant.pemPublicKeyHeader) + PemConstant.pemPublicKeyHeader.length,
                this.exportedKeyPair.indexOf(PemConstant.pemPublicKeyFooter))),
            {
                name: 'RSASSA-PKCS1-v1_5',
                //  modulusLength: 2048,
                //  publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256',
            },
            true,
            ['verify']
        );


        this.keyPair.privateKey = await CryptoModule.gCrypto.subtle.importKey(
            'pkcs8',
            Base64.decode(this.exportedKeyPair.substring(this.exportedKeyPair.indexOf(PemConstant.pemPrivateKeyHeader) + PemConstant.pemPrivateKeyHeader.length,
                this.exportedKeyPair.indexOf(PemConstant.pemPrivateKeyFooter))),
            {
                name: 'RSASSA-PKCS1-v1_5',
                hash: 'SHA-256',
            },
            true,
            ['sign']
        );
    }
}
