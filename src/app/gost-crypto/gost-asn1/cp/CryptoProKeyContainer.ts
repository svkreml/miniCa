import {DERElement} from 'asn1-ts';
import {GostKeys} from './gost-keys';
import {GostKeyContainer, GostKeyContainerName, GostPrivateKeys, GostPrivateMasks} from './CP';

export class CryptoProKeyContainer {
    gostKeys: GostKeys = new GostKeys();
    header: GostKeyContainer;
    name: GostKeyContainerName;
    primary: GostPrivateKeys;
    masks: GostPrivateMasks;
    primary2: GostPrivateKeys;
    masks2: GostPrivateMasks;

/*
    public verify(keyPassword: string) // <editor-fold defaultstate="collapsed">
    {

        let algorithm;

        let content = this.header.keyContainerContent;
        algorithm = content.primaryPrivateKeyParameters.privateKeyAlgorithm;
        // Verify container MAC
        let hmac = this.gostKeys.computeContainerMAC(algorithm, content);

        if (!this.gostKeys.equalBuffers(hmac, this.header.hmacKeyContainerContent)) {
            throw new Error('Container is not valid.');
        }
        // Verify key password MAC
        let needPassword: boolean = content.attributes.indexOf('kccaSoftPassword') >= 0;
        if (!keyPassword && needPassword) {
            throw new Error('Password is required');
        }
        if (keyPassword && !needPassword) {
            throw new Error('Password is not reqiured.');
        }
        if (keyPassword)
        // Derive password
        {
            return this.gostKeys.computePasswordMAC(algorithm, keyPassword, content.primaryFP).then(hmac => {
                if (!this.gostKeys.equalBuffers(hmac, content.hmacPassword)) {
                    throw new Error('Password is not valid.');
                }
                return self;
            });
        }
        return self;

    }*/
}
