import { KeyManagementServiceClient } from '@google-cloud/kms';
import { ISigningStrategy } from "wbn-sign/lib/wbn-sign";
import { KeyObject, createPublicKey, createHash } from 'crypto';

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

        const [response] = await client.asymmetricSign({
            name: client.cryptoKeyVersionPath(this.projectId, this.locationId, this.keyringId, this.keyId, this.versionId),
            digest: {
                sha256: createHash('sha256').update(data).digest()
            }
        });

        if (response.signature instanceof Uint8Array){
            return response.signature;
        }
        throw 'ERROR while signing';
    }

    async getPublicKey(): Promise<KeyObject> {
        const client = new KeyManagementServiceClient();
        const name = client.cryptoKeyVersionPath(this.projectId, this.locationId, this.keyringId, this.keyId, this.versionId);
        const [publicKey] = await client.getPublicKey({
            name: name
        });
        if (typeof publicKey.pem === 'string') {
            return createPublicKey(publicKey.pem as string);
        }
        throw 'ERROR while getting public key';
    }

    private projectId: string;
    private locationId: string;
    private keyringId: string;
    private keyId: string;
    private versionId: string;
}

export { GCPWbnSigner }; 
