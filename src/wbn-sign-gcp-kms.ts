import { KeyManagementServiceClient } from '@google-cloud/kms';
import { ISigningStrategy } from "wbn-sign/lib/wbn-sign";
import { KeyObject, createPublicKey, createHash } from 'crypto';

class GCPWbnSigner implements ISigningStrategy {
    private kmsClient: KeyManagementServiceClient;

    constructor(
        private projectId: string,
        private locationId: string,
        private keyringId: string,
        private keyId: string,
        private versionId: string,
        kmsClient?: KeyManagementServiceClient
    ) {
        this.kmsClient = kmsClient || new KeyManagementServiceClient();
    }

    async sign(data: Uint8Array): Promise<Uint8Array> {
        const [response] = await this.kmsClient.asymmetricSign({
            name: this.kmsClient.cryptoKeyVersionPath(this.projectId, this.locationId, this.keyringId, this.keyId, this.versionId),
            digest: {
                sha256: createHash('sha256').update(data).digest()
            }
        });

        if (response.signature instanceof Uint8Array){
            return response.signature;
        }
        throw new Error('No signature in response!');
    }

    async getPublicKey(): Promise<KeyObject> {
        const [publicKey] = await this.kmsClient.getPublicKey({
            name: this.kmsClient.cryptoKeyVersionPath(this.projectId, this.locationId, this.keyringId, this.keyId, this.versionId)
        });
        if (typeof publicKey.pem === 'string') {
            return createPublicKey(publicKey.pem as string);
        }
        throw new Error('No public key in response!');
    }
}

export { GCPWbnSigner }; 
