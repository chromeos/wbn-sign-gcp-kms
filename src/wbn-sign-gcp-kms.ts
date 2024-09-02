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
import * as wbnSign from 'wbn-sign';
import { KeyObject, createPublicKey, createHash } from 'crypto';

/**
 * Represents the key ID information for a Google Cloud KMS key.
 * Mandatory fields: project, location, keyring, key, version.
 */
export interface GCPKeyInfo {
  project: string;
  location: string;
  keyring: string;
  key: string;
  version: string;
}

/**
 * Represents the key information with added web bundle ID.
 */
export interface GCPKeyInfoWithBundleId extends GCPKeyInfo {
  webBundleId: string;
}

/**
 * Google Cloud Platform KMS based implementation of the ISigningStrategy.
 */
export class GCPWbnSigner implements ISigningStrategy {
  #kmsClient: KeyManagementServiceClient;
  #keyInfo: GCPKeyInfo;

  /**
   * Constructs a new GCPWbnSigner.
   * @param {GCPKeyInfo} keyInfo The key ID information.
   * @param {KeyManagementServiceClient} [kmsClient] Optional pre-constructed KeyManagementServiceClient - to be used for testing only.
   */
  constructor(keyInfo: GCPKeyInfo, kmsClient?: KeyManagementServiceClient) {
    this.#kmsClient = kmsClient || new KeyManagementServiceClient();
    this.#keyInfo = keyInfo;
  }

  /**
   * Signs the given data using the Google Cloud KMS service.
   * @param {Uint8Array} data The data to sign.
   * @returns {Promise<Uint8Array>} A promise that resolves with the signature.
   */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    const [response] = await this.#kmsClient.asymmetricSign({
      name: this.#kmsClient.cryptoKeyVersionPath(
        this.#keyInfo.project,
        this.#keyInfo.location,
        this.#keyInfo.keyring,
        this.#keyInfo.key,
        this.#keyInfo.version
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

  /**
   * Gets the public key from the Google Cloud KMS service.
   * @returns {Promise<KeyObject>} A promise that resolves with the public key.
   */
  async getPublicKey(): Promise<KeyObject> {
    const [publicKey] = await this.#kmsClient.getPublicKey({
      name: this.#kmsClient.cryptoKeyVersionPath(
        this.#keyInfo.project,
        this.#keyInfo.location,
        this.#keyInfo.keyring,
        this.#keyInfo.key,
        this.#keyInfo.version
      ),
    });
    if (typeof publicKey.pem === 'string') {
      return createPublicKey(publicKey.pem as string);
    }
    throw new Error('No public key in response!');
  }
}

/**
 * Signs a web bundle using a list of Google Cloud KMS keys.
 * @param {Uint8Array} webBundle The web bundle to sign.
 * @param {GCPKeyInfo[]} keyInfos The list of key ID information.
 * @param {string | undefined} [webBundleId] The web bundle ID to use (if not provided, bundle ID will be automatically generated from the first key).
 * @returns {Promise<Uint8Array>} A promise that resolves with the signed web bundle.
 */
export async function signBundle(
  webBundle: Uint8Array,
  keyInfos: GCPKeyInfo[],
  webBundleId: string | undefined = undefined
): Promise<Uint8Array> {
  if (keyInfos.length === 0) {
    throw new Error('No key IDs provided!');
  }
  const signers = await Promise.all(
    keyInfos.map(async (keyInfo) => {
      const signer = new GCPWbnSigner(keyInfo);
      return {
        signer,
        webBundleId: new wbnSign.WebBundleId(
          await signer.getPublicKey()
        ).serialize(),
      };
    })
  );
  if (webBundleId === undefined) {
    console.log(
      'No Web Bundle Id provided, will deduct it from the first key:',
      { ...keyInfos[0], webBundleId: signers[0].webBundleId }
    );
  }
  const { signedWebBundle } = await new wbnSign.IntegrityBlockSigner(
    webBundle,
    webBundleId || signers[0].webBundleId,
    signers.map(({ signer }) => signer)
  ).sign();
  return signedWebBundle;
}

/**
 * Gets the web bundle IDs for a list of Google Cloud KMS keys.
 * @param {GCPKeyInfo[]} keyInfos The list of key ID information.
 * @returns {Promise<GCPKeyInfoWithBundleId[]>} A promise that resolves with the list of key ID information with the web bundle IDs.
 */
export async function getWebBundleIds(
  keyInfos: GCPKeyInfo[]
): Promise<GCPKeyInfoWithBundleId[]> {
  return Promise.all(
    keyInfos.map(async (keyInfo) => {
      const signer = new GCPWbnSigner(keyInfo);
      return {
        ...keyInfo,
        webBundleId: new wbnSign.WebBundleId(
          await signer.getPublicKey()
        ).serialize(),
      };
    })
  );
}
