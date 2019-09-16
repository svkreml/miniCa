import {Component, OnInit} from '@angular/core';
import {Base64} from '../gost-crypto/gost-coding/gost-coding';

@Component({
    selector: 'app-generate-key-pair',
    templateUrl: './generate-key-pair.component.html',
    styleUrls: ['./generate-key-pair.component.css']
})
export class GenerateKeyPairComponent implements OnInit {
    input: string;
    signature: string;
    verifyResult: string;


    pemPrivateKeyHeader = '-----BEGIN PRIVATE KEY-----';
    pemPrivateKeyFooter = '-----END PRIVATE KEY-----';
    pemPublicKeyHeader = '-----BEGIN PUBLIC KEY-----';
    pemPublicKeyFooter = '-----END PUBLIC KEY-----';


    keyPair: CryptoKeyPair;
    exportedKeyPair: string;

    constructor() {
    }

    ngOnInit() {
    }

    generateKeyPair() {
        console.log('Generate button clicked!');

        crypto.subtle.generateKey(
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

        let result: boolean = await crypto.subtle.verify(
            this.keyPair.publicKey.algorithm.name,
            this.keyPair.publicKey,
            Base64.decode(this.signature),
            this.encodeMessage(this.input),
        );
        this.verifyResult = result ? 'valid' : 'invalid';
    }

    sign() {
        crypto.subtle.sign(
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


        const wrapped: ArrayBuffer = await crypto.subtle.exportKey(
            'spki',
            this.keyPair.publicKey,
        );

        this.exportedKeyPair += this.pemPublicKeyHeader + '\n';
        this.exportedKeyPair += Base64.encode(wrapped);
        this.exportedKeyPair += '\n' + this.pemPublicKeyFooter + '\n';


        const wrapped2: ArrayBuffer = await crypto.subtle.exportKey(
            'pkcs8',
            this.keyPair.privateKey,
        );
        this.exportedKeyPair += this.pemPrivateKeyHeader + '\n';
        this.exportedKeyPair += Base64.encode(wrapped2);
        this.exportedKeyPair += '\n' + this.pemPrivateKeyFooter;
    }


    async importKeyPair() {
        // this.keyPair = new CryptoKeyPair();


        this.keyPair.publicKey = await crypto.subtle.importKey(
            'spki',
            Base64.decode(this.exportedKeyPair.substring(this.exportedKeyPair.indexOf(this.pemPublicKeyHeader) + this.pemPublicKeyHeader.length,
                this.exportedKeyPair.indexOf(this.pemPublicKeyFooter))),
            {
                name: 'RSASSA-PKCS1-v1_5',
                //  modulusLength: 2048,
                //  publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256',
            },
            true,
            ['verify']
        );


        this.keyPair.privateKey = await crypto.subtle.importKey(
            'pkcs8',
            Base64.decode(this.exportedKeyPair.substring(this.exportedKeyPair.indexOf(this.pemPrivateKeyHeader) + this.pemPrivateKeyHeader.length,
                this.exportedKeyPair.indexOf(this.pemPrivateKeyFooter))),
            {
                name: 'RSASSA-PKCS1-v1_5',
                hash: 'SHA-256',
            },
            true,
            ['sign']
        );
    }
}
