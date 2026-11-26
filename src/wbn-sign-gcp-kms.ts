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

import { KeyManagementServiceClient, protos } from '@google-cloud/kms';
import { ISigningStrategy } from 'wbn-sign/lib/wbn-sign';
import * as wbnSign from 'wbn-sign';
import { KeyObject, createPublicKey } from 'crypto';
import { crc32c, parseCrc32cValue } from './crc32c.js';

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
 * Single Cloud KMS resource segment for location, keyring, key, or version.
 */
const KMS_RESOURCE_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * GCP project identifier or number, including domain-scoped IDs such as
 * `example.com:my-project`.
 */
const GCP_PROJECT_SEGMENT_PATTERN =
  /^[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?(?::[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?)?$/;

type SupportedKmsAlgorithm = 'EC_SIGN_P256_SHA256' | 'EC_SIGN_ED25519';

const { CryptoKeyVersionAlgorithm } =
  protos.google.cloud.kms.v1.CryptoKeyVersion;

function normalizeSupportedAlgorithm(
  algorithm:
    | protos.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm
    | keyof typeof protos.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm
    | null
    | undefined,
): SupportedKmsAlgorithm | null {
  switch (algorithm) {
    case 'EC_SIGN_P256_SHA256':
    case CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256:
      return 'EC_SIGN_P256_SHA256';
    case 'EC_SIGN_ED25519':
    case CryptoKeyVersionAlgorithm.EC_SIGN_ED25519:
      return 'EC_SIGN_ED25519';
    default:
      return null;
  }
}

function doesKeyMatchAlgorithm(
  key: KeyObject,
  algorithm: SupportedKmsAlgorithm,
): boolean {
  switch (algorithm) {
    case 'EC_SIGN_P256_SHA256':
      return (
        key.asymmetricKeyType === 'ec' &&
        key.asymmetricKeyDetails?.namedCurve === 'prime256v1'
      );
    case 'EC_SIGN_ED25519':
      return key.asymmetricKeyType === 'ed25519';
  }
}

/**
 * Validates that the input is an object whose mandatory Cloud KMS key fields
 * are single resource-path segments, and returns a normalized copy.
 * @param {unknown} keyInfo The key ID information to validate.
 * @returns {GCPKeyInfo} A validated copy of the key ID information.
 */
export function validateKeyInfo(keyInfo: unknown): GCPKeyInfo {
  if (
    typeof keyInfo !== 'object' ||
    keyInfo === null ||
    Array.isArray(keyInfo)
  ) {
    throw new Error('Invalid GCPKeyInfo: expected a JSON object');
  }
  const raw = keyInfo as Record<string, unknown>;

  const readField = (field: keyof GCPKeyInfo): string => {
    if (!Object.prototype.hasOwnProperty.call(raw, field)) {
      throw new Error(`Invalid GCPKeyInfo.${field}: missing required field`);
    }
    const value = raw[field];
    if (typeof value !== 'string') {
      throw new Error(
        `Invalid GCPKeyInfo.${field}: expected a string, got ${JSON.stringify(value)}`,
      );
    }
    return value;
  };

  const project = readField('project');
  if (!GCP_PROJECT_SEGMENT_PATTERN.test(project) || project.includes('..')) {
    throw new Error(
      `Invalid GCPKeyInfo.project: expected a single GCP project segment, got ${JSON.stringify(project)}`,
    );
  }

  const location = readField('location');
  const keyring = readField('keyring');
  const key = readField('key');
  const version = readField('version');

  for (const [field, value] of [
    ['location', location],
    ['keyring', keyring],
    ['key', key],
    ['version', version],
  ] as const) {
    if (!KMS_RESOURCE_SEGMENT_PATTERN.test(value)) {
      throw new Error(
        `Invalid GCPKeyInfo.${field}: expected a single path segment matching ${KMS_RESOURCE_SEGMENT_PATTERN}, got ${JSON.stringify(value)}`,
      );
    }
  }

  return { project, location, keyring, key, version };
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
    this.#keyInfo = validateKeyInfo(keyInfo);
  }

  #getKeyVersionName(): string {
    return this.#kmsClient.cryptoKeyVersionPath(
      this.#keyInfo.project,
      this.#keyInfo.location,
      this.#keyInfo.keyring,
      this.#keyInfo.key,
      this.#keyInfo.version,
    );
  }

  /**
   * Signs the given data using the Google Cloud KMS service.
   * @param {Uint8Array} data The data to sign.
   * @returns {Promise<Uint8Array>} A promise that resolves with the signature.
   */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    const name = this.#getKeyVersionName();
    const dataCrc32c = crc32c(data);
    const [response] = await this.#kmsClient.asymmetricSign({
      name,
      data,
      dataCrc32c: { value: dataCrc32c },
    });

    if (!(response.signature instanceof Uint8Array)) {
      throw new Error('No signature in response!');
    }
    if (response.name !== name) {
      throw new Error(
        'asymmetricSign: response failed integrity verification (name mismatch)',
      );
    }
    // Fails closed without retrying automatically so callers control retry policy.
    if (response.verifiedDataCrc32c !== true) {
      throw new Error(
        'asymmetricSign: response failed integrity verification (request data CRC32C not verified)',
      );
    }
    if (
      parseCrc32cValue(response.signatureCrc32c) !== crc32c(response.signature)
    ) {
      throw new Error(
        'asymmetricSign: response failed integrity verification (signature CRC32C mismatch)',
      );
    }
    return response.signature;
  }

  /**
   * Gets the public key from the Google Cloud KMS service.
   * @returns {Promise<KeyObject>} A promise that resolves with the public key.
   */
  async getPublicKey(): Promise<KeyObject> {
    const name = this.#getKeyVersionName();
    const [publicKey] = await this.#kmsClient.getPublicKey({ name });
    if (typeof publicKey.pem !== 'string') {
      throw new Error('No public key in response!');
    }
    if (publicKey.name !== name) {
      throw new Error(
        'getPublicKey: response failed integrity verification (name mismatch)',
      );
    }
    if (
      parseCrc32cValue(publicKey.pemCrc32c) !==
      crc32c(Buffer.from(publicKey.pem, 'utf8'))
    ) {
      throw new Error(
        'getPublicKey: response failed integrity verification (PEM CRC32C mismatch)',
      );
    }
    const algorithm = normalizeSupportedAlgorithm(publicKey.algorithm);
    if (algorithm === null) {
      throw new Error(
        `getPublicKey: unsupported signing algorithm: ${String(publicKey.algorithm)}`,
      );
    }
    const keyObject = createPublicKey(publicKey.pem);
    if (!doesKeyMatchAlgorithm(keyObject, algorithm)) {
      throw new Error(
        `getPublicKey: public key PEM does not match declared algorithm ${algorithm}`,
      );
    }
    return keyObject;
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
  webBundleId: string | undefined = undefined,
): Promise<Uint8Array> {
  if (keyInfos.length === 0) {
    throw new Error('No key IDs provided!');
  }
  const signers = await Promise.all(
    keyInfos.map(async (keyInfo) => {
      const validatedKeyInfo = validateKeyInfo(keyInfo);
      const signer = new GCPWbnSigner(validatedKeyInfo);
      return {
        keyInfo: validatedKeyInfo,
        signer,
        webBundleId: new wbnSign.WebBundleId(
          await signer.getPublicKey(),
        ).serialize(),
      };
    }),
  );
  if (webBundleId === undefined) {
    console.log(
      'No Web Bundle Id provided, will deduct it from the first key:',
      { ...signers[0].keyInfo, webBundleId: signers[0].webBundleId },
    );
  }
  const { signedWebBundle } = await new wbnSign.IntegrityBlockSigner(
    webBundle,
    webBundleId || signers[0].webBundleId,
    signers.map(({ signer }) => signer),
  ).sign();
  return signedWebBundle;
}

/**
 * Gets the web bundle IDs for a list of Google Cloud KMS keys.
 * @param {GCPKeyInfo[]} keyInfos The list of key ID information.
 * @returns {Promise<GCPKeyInfoWithBundleId[]>} A promise that resolves with the list of key ID information with the web bundle IDs.
 */
export async function getWebBundleIds(
  keyInfos: GCPKeyInfo[],
): Promise<GCPKeyInfoWithBundleId[]> {
  return Promise.all(
    keyInfos.map(async (keyInfo) => {
      const validatedKeyInfo = validateKeyInfo(keyInfo);
      const signer = new GCPWbnSigner(validatedKeyInfo);
      return {
        ...validatedKeyInfo,
        webBundleId: new wbnSign.WebBundleId(
          await signer.getPublicKey(),
        ).serialize(),
      };
    }),
  );
}
