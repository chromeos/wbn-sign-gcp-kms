import { KeyManagementServiceClient } from '@google-cloud/kms';
import { ISigningStrategy } from "wbn-sign/lib/wbn-sign";
import { KeyObject, createPublicKey } from 'crypto';

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
        
        const keyObject = createPublicKey(publicKey.pem as string);
        return keyObject;
    }

    private projectId: string;
    private locationId: string;
    private keyringId: string;
    private keyId: string;
    private versionId: string;
}

export { GCPWbnSigner }; 
