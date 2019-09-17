import {OnInit} from '@angular/core';

export class CryptoModule implements OnInit {
    static gCrypto = crypto;

    ngOnInit(): void {
        if (crypto)
            CryptoModule.gCrypto = crypto;
        else if (window.crypto)
            CryptoModule.gCrypto = window.crypto;
        // @ts-ignore
        else if (window.msCrypto)
        // @ts-ignore
            CryptoModule.gCrypto = window.msCrypto;
        else {
            alert('Не удалось получить доступ к крипто библиотеке');
        }
    }
}

