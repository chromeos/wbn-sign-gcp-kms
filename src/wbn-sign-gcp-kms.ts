import { KeyManagementServiceClient } from '@google-cloud/kms';
import { ISigningStrategy } from "wbn-sign/lib/wbn-sign";
import { KeyObject } from 'crypto';

function str2ab(str: string) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

async function pemToKeyObject(pem: string): Promise<KeyObject> {
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length - 1);
    const binaryDerString = atob(pemContents);
    const binaryDer = str2ab(binaryDerString);

    return KeyObject.from(await crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
        name: "ECDSA",
        namedCurve: "P-256"
        },
        true,
        []
    ));
}

class GCPWbnSigner implements ISigningStrategy {
   constructor(projectId: string, locationId: string, keyringId: string, keyId: string, versionId: string) {
        this.projectId = projectId;
        this.locationId = locationId;
        this.keyringId = keyringId;
        this.keyId = keyId;
        this.versionId = versionId;
    }

    async sign(data: Uint8Array): Promise<Uint8Array> {
        const client = new KeyManagementServiceClient();

        const name = client.cryptoKeyVersionPath(this.projectId, this.locationId, this.keyringId, this.keyId, this.versionId);
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256');
        hash.update(data);

        const request = {
            name,
            digest: {
                sha256: hash.digest()
            }
        };

        const [response] = await client.asymmetricSign(request);
        if (response.signature instanceof Uint8Array){
            return response.signature;
        }
        throw 'ERROR';
    }

    async getPublicKey(): Promise<KeyObject> {
        const client = new KeyManagementServiceClient();
        const name = client.cryptoKeyVersionPath(this.projectId, this.locationId, this.keyringId, this.keyId, this.versionId);
        const [publicKey] = await client.getPublicKey({
            name: name
        });
        
        const keyObject = await pemToKeyObject(publicKey.pem as string);
        return keyObject;
    }

    private projectId: string;
    private locationId: string;
    private keyringId: string;
    private keyId: string;
    private versionId: string;
}

export { GCPWbnSigner }; 
