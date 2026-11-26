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

import { GCPWbnSigner, validateKeyInfo } from '../lib/wbn-sign-gcp-kms.js';
import { crc32c } from '../lib/crc32c.js';
import { createPublicKey, generateKeyPairSync } from 'crypto';

const TEST_P256_PUBLIC_KEY = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
}).publicKey.export({ type: 'spki', format: 'pem' });

const TEST_ED25519_PUBLIC_KEY = generateKeyPairSync('ed25519').publicKey.export(
  { type: 'spki', format: 'pem' },
);

const TEST_SECP256K1_PUBLIC_KEY = generateKeyPairSync('ec', {
  namedCurve: 'secp256k1',
}).publicKey.export({ type: 'spki', format: 'pem' });

const KEY_VERSION_NAME = 'path/to/key/version';

function makePublicKeyResponse(pem, overrides = {}) {
  return {
    pem,
    pemCrc32c: { value: String(crc32c(Buffer.from(pem, 'utf8'))) },
    name: KEY_VERSION_NAME,
    algorithm: 'EC_SIGN_P256_SHA256',
    ...overrides,
  };
}

function makeSignResponse(signature, overrides = {}) {
  return {
    signature,
    signatureCrc32c: { value: String(crc32c(signature)) },
    verifiedDataCrc32c: true,
    name: KEY_VERSION_NAME,
    ...overrides,
  };
}

describe('GCPWbnSigner', () => {
  let signer;
  let mockKmsClient;

  beforeEach(() => {
    const defaultSignature = new Uint8Array([4, 5, 6]);
    mockKmsClient = {
      cryptoKeyVersionPath: jasmine
        .createSpy('cryptoKeyVersionPath')
        .and.returnValue(KEY_VERSION_NAME),
      asymmetricSign: jasmine
        .createSpy('asymmetricSign')
        .and.resolveTo([makeSignResponse(defaultSignature)]),
      getPublicKey: jasmine
        .createSpy('getPublicKey')
        .and.resolveTo([makePublicKeyResponse(TEST_P256_PUBLIC_KEY)]),
    };

    signer = new GCPWbnSigner(
      {
        project: 'projectId',
        location: 'locationId',
        keyring: 'keyringId',
        key: 'keyId',
        version: 'versionId',
      },
      mockKmsClient,
    );
  });

  it('should sign data and send dataCrc32c', async () => {
    const testData = new Uint8Array([1, 2, 3]);
    const expectedSignature = new Uint8Array([4, 5, 6]);

    const signature = await signer.sign(testData);

    expect(signature).toEqual(expectedSignature);
    expect(mockKmsClient.cryptoKeyVersionPath).toHaveBeenCalledWith(
      'projectId',
      'locationId',
      'keyringId',
      'keyId',
      'versionId',
    );
    expect(mockKmsClient.asymmetricSign).toHaveBeenCalledWith({
      name: KEY_VERSION_NAME,
      data: testData,
      dataCrc32c: { value: crc32c(testData) },
    });
  });

  it('should throw error when signing fails', async () => {
    mockKmsClient.asymmetricSign.and.rejectWith(new Error('Signing failed'));

    await expectAsync(signer.sign(new Uint8Array())).toBeRejectedWithError(
      'Signing failed',
    );
  });

  it('should throw error when returned invalid object as signature', async () => {
    mockKmsClient.asymmetricSign.and.returnValue([{ not_signature: true }]);

    await expectAsync(signer.sign(new Uint8Array())).toBeRejectedWithError(
      'No signature in response!',
    );
  });

  it('should reject asymmetricSign response with mismatched name', async () => {
    mockKmsClient.asymmetricSign.and.resolveTo([
      makeSignResponse(new Uint8Array([4, 5, 6]), {
        name: 'path/to/OTHER/version',
      }),
    ]);

    await expectAsync(
      signer.sign(new Uint8Array([1, 2, 3])),
    ).toBeRejectedWithError(/name mismatch/);
  });

  it('should accept numeric and Long-like signatureCrc32c values', async () => {
    const expectedSignature = new Uint8Array([4, 5, 6]);
    const expectedCrc = crc32c(expectedSignature);

    mockKmsClient.asymmetricSign.and.resolveTo([
      makeSignResponse(expectedSignature, {
        signatureCrc32c: { value: expectedCrc },
      }),
    ]);
    expect(await signer.sign(new Uint8Array([1, 2, 3]))).toEqual(
      expectedSignature,
    );

    mockKmsClient.asymmetricSign.and.resolveTo([
      makeSignResponse(expectedSignature, {
        signatureCrc32c: { value: { toString: () => String(expectedCrc) } },
      }),
    ]);
    expect(await signer.sign(new Uint8Array([1, 2, 3]))).toEqual(
      expectedSignature,
    );
  });

  it('should reject asymmetricSign response when verifiedDataCrc32c is not true', async () => {
    mockKmsClient.asymmetricSign.and.resolveTo([
      makeSignResponse(new Uint8Array([4, 5, 6]), {
        verifiedDataCrc32c: false,
      }),
    ]);

    await expectAsync(
      signer.sign(new Uint8Array([1, 2, 3])),
    ).toBeRejectedWithError(/request data CRC32C not verified/);

    mockKmsClient.asymmetricSign.and.resolveTo([
      makeSignResponse(new Uint8Array([4, 5, 6]), {
        verifiedDataCrc32c: undefined,
      }),
    ]);

    await expectAsync(
      signer.sign(new Uint8Array([1, 2, 3])),
    ).toBeRejectedWithError(/request data CRC32C not verified/);
  });

  it('should reject asymmetricSign response with mismatched or missing signatureCrc32c', async () => {
    mockKmsClient.asymmetricSign.and.resolveTo([
      makeSignResponse(new Uint8Array([4, 5, 6]), {
        signatureCrc32c: { value: '0' },
      }),
    ]);
    await expectAsync(
      signer.sign(new Uint8Array([1, 2, 3])),
    ).toBeRejectedWithError(/signature CRC32C mismatch/);

    mockKmsClient.asymmetricSign.and.resolveTo([
      makeSignResponse(new Uint8Array(0), {
        signatureCrc32c: { value: null },
      }),
    ]);
    await expectAsync(
      signer.sign(new Uint8Array([1, 2, 3])),
    ).toBeRejectedWithError(/signature CRC32C mismatch/);
  });

  it('should get P-256 public key and accept numeric KMS algorithm enum', async () => {
    const expectedPublicKey = createPublicKey(TEST_P256_PUBLIC_KEY);

    const publicKey = await signer.getPublicKey();

    expect(publicKey.equals(expectedPublicKey)).toBeTrue();
    expect(mockKmsClient.cryptoKeyVersionPath).toHaveBeenCalledWith(
      'projectId',
      'locationId',
      'keyringId',
      'keyId',
      'versionId',
    );
    expect(mockKmsClient.getPublicKey).toHaveBeenCalledWith({
      name: KEY_VERSION_NAME,
    });

    mockKmsClient.getPublicKey.and.resolveTo([
      makePublicKeyResponse(TEST_P256_PUBLIC_KEY, { algorithm: 12 }),
    ]);
    expect((await signer.getPublicKey()).equals(expectedPublicKey)).toBeTrue();
  });

  it('should get Ed25519 public key and accept numeric KMS algorithm enum', async () => {
    const expectedPublicKey = createPublicKey(TEST_ED25519_PUBLIC_KEY);
    mockKmsClient.getPublicKey.and.resolveTo([
      makePublicKeyResponse(TEST_ED25519_PUBLIC_KEY, {
        algorithm: 'EC_SIGN_ED25519',
      }),
    ]);
    expect((await signer.getPublicKey()).equals(expectedPublicKey)).toBeTrue();

    mockKmsClient.getPublicKey.and.resolveTo([
      makePublicKeyResponse(TEST_ED25519_PUBLIC_KEY, { algorithm: 40 }),
    ]);
    expect((await signer.getPublicKey()).equals(expectedPublicKey)).toBeTrue();
  });

  it('should throw error when getting public key fails', async () => {
    mockKmsClient.getPublicKey.and.rejectWith(
      new Error('Get Public Key failed'),
    );

    await expectAsync(signer.getPublicKey()).toBeRejectedWithError(
      'Get Public Key failed',
    );
  });

  it('should throw error when got unexpected object as public key', async () => {
    mockKmsClient.getPublicKey.and.returnValue([{ not_pem: true }]);

    await expectAsync(signer.getPublicKey()).toBeRejectedWithError(
      'No public key in response!',
    );
  });

  it('should reject public key with mismatched name', async () => {
    mockKmsClient.getPublicKey.and.resolveTo([
      makePublicKeyResponse(TEST_P256_PUBLIC_KEY, {
        name: 'path/to/OTHER/version',
      }),
    ]);

    await expectAsync(signer.getPublicKey()).toBeRejectedWithError(
      /name mismatch/,
    );
  });

  it('should reject public key with mismatched or missing pemCrc32c', async () => {
    mockKmsClient.getPublicKey.and.resolveTo([
      makePublicKeyResponse(TEST_P256_PUBLIC_KEY, {
        pemCrc32c: { value: '0' },
      }),
    ]);
    await expectAsync(signer.getPublicKey()).toBeRejectedWithError(
      /PEM CRC32C mismatch/,
    );

    mockKmsClient.getPublicKey.and.resolveTo([
      makePublicKeyResponse(TEST_P256_PUBLIC_KEY, {
        pemCrc32c: { value: null },
      }),
    ]);
    await expectAsync(signer.getPublicKey()).toBeRejectedWithError(
      /PEM CRC32C mismatch/,
    );

    mockKmsClient.getPublicKey.and.resolveTo([
      makePublicKeyResponse(TEST_P256_PUBLIC_KEY, { pemCrc32c: undefined }),
    ]);
    await expectAsync(signer.getPublicKey()).toBeRejectedWithError(
      /PEM CRC32C mismatch/,
    );
  });

  it('should reject public key with unsupported or missing signing algorithm', async () => {
    for (const algorithm of ['RSA_SIGN_PKCS1_4096_SHA512', null, undefined]) {
      mockKmsClient.getPublicKey.and.resolveTo([
        makePublicKeyResponse(TEST_P256_PUBLIC_KEY, { algorithm }),
      ]);

      await expectAsync(signer.getPublicKey()).toBeRejectedWithError(
        /unsupported signing algorithm/,
      );
    }
  });

  it('should reject public key whose PEM does not match declared KMS algorithm', async () => {
    mockKmsClient.getPublicKey.and.resolveTo([
      makePublicKeyResponse(TEST_SECP256K1_PUBLIC_KEY, {
        algorithm: 'EC_SIGN_P256_SHA256',
      }),
    ]);
    await expectAsync(signer.getPublicKey()).toBeRejectedWithError(
      /does not match declared algorithm/,
    );

    mockKmsClient.getPublicKey.and.resolveTo([
      makePublicKeyResponse(TEST_ED25519_PUBLIC_KEY, {
        algorithm: 'EC_SIGN_P256_SHA256',
      }),
    ]);
    await expectAsync(signer.getPublicKey()).toBeRejectedWithError(
      /does not match declared algorithm/,
    );

    mockKmsClient.getPublicKey.and.resolveTo([
      makePublicKeyResponse(TEST_P256_PUBLIC_KEY, {
        algorithm: 'EC_SIGN_ED25519',
      }),
    ]);
    await expectAsync(signer.getPublicKey()).toBeRejectedWithError(
      /does not match declared algorithm/,
    );
  });

  it('should accept domain-scoped GCP project IDs and strip extra properties', () => {
    const valid = validateKeyInfo({
      project: 'google.com:my-iwa-project',
      location: 'global',
      keyring: 'prod_ring-1',
      key: 'signing_key-1',
      version: '1',
      extra: 'ignored',
    });
    expect(valid).toEqual({
      project: 'google.com:my-iwa-project',
      location: 'global',
      keyring: 'prod_ring-1',
      key: 'signing_key-1',
      version: '1',
    });
  });

  it('should reject keyInfo fields with path traversal or invalid characters', () => {
    const base = {
      project: 'projectId',
      location: 'locationId',
      keyring: 'keyringId',
      key: 'keyId',
      version: '1',
    };

    const badCases = [
      { ...base, version: '1/../cryptoKeyVersions/999' },
      { ...base, version: '..' },
      { ...base, version: '.' },
      { ...base, key: 'key/other' },
      { ...base, keyring: '{injected}' },
      { ...base, location: 'global ' },
      { ...base, project: 'google.com:proj/../other' },
      { ...base, project: 'google.com:a..b' },
      { ...base, project: '..' },
      { ...base, project: 'a:b:c' },
    ];

    for (const keyInfo of badCases) {
      expect(() => new GCPWbnSigner(keyInfo, mockKmsClient)).toThrowError(
        /Invalid GCPKeyInfo\./,
      );
    }
  });

  it('should reject non-object, missing, or non-string keyInfo inputs', () => {
    expect(() => validateKeyInfo(null)).toThrowError(/Invalid GCPKeyInfo/);
    expect(() => validateKeyInfo([])).toThrowError(/Invalid GCPKeyInfo/);
    expect(() => validateKeyInfo('str')).toThrowError(/Invalid GCPKeyInfo/);
    expect(() =>
      validateKeyInfo({
        project: 'projectId',
        location: 'locationId',
        keyring: 'keyringId',
        key: 'keyId',
      }),
    ).toThrowError(/Invalid GCPKeyInfo\.version/);
    expect(
      () =>
        new GCPWbnSigner(
          {
            project: 'projectId',
            location: 'locationId',
            keyring: 'keyringId',
            key: 'keyId',
            version: ['1', '2'],
          },
          mockKmsClient,
        ),
    ).toThrowError(/Invalid GCPKeyInfo\.version/);
  });

  it('should not be affected by post-construction mutation of keyInfo', async () => {
    const keyInfo = {
      project: 'projectId',
      location: 'locationId',
      keyring: 'keyringId',
      key: 'keyId',
      version: '1',
    };
    const isolatedSigner = new GCPWbnSigner(keyInfo, mockKmsClient);
    keyInfo.version = '1/../cryptoKeyVersions/999';

    await isolatedSigner.sign(new Uint8Array([1, 2, 3]));

    expect(mockKmsClient.cryptoKeyVersionPath).toHaveBeenCalledWith(
      'projectId',
      'locationId',
      'keyringId',
      'keyId',
      '1',
    );
  });
});
