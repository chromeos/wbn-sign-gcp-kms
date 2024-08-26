/**
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { KeyManagementServiceClient } from '@google-cloud/kms';
import { ISigningStrategy } from 'wbn-sign/lib/wbn-sign';
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
      name: this.kmsClient.cryptoKeyVersionPath(
        this.projectId,
        this.locationId,
        this.keyringId,
        this.keyId,
        this.versionId
      ),
      digest: {
        sha256: createHash('sha256').update(data).digest(),
      },
    });

    if (response.signature instanceof Uint8Array) {
      return response.signature;
    }
    throw new Error('No signature in response!');
  }

  async getPublicKey(): Promise<KeyObject> {
    const [publicKey] = await this.kmsClient.getPublicKey({
      name: this.kmsClient.cryptoKeyVersionPath(
        this.projectId,
        this.locationId,
        this.keyringId,
        this.keyId,
        this.versionId
      ),
    });
    if (typeof publicKey.pem === 'string') {
      return createPublicKey(publicKey.pem as string);
    }
    throw new Error('No public key in response!');
  }
}

export { GCPWbnSigner };
