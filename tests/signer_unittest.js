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

import { GCPWbnSigner } from '../lib/wbn-sign-gcp-kms.js';
import { crc32c } from '../lib/crc32c.js';
import { createPublicKey } from 'crypto';

const KEY_VERSION_NAME = 'path/to/key/version';

const TEST_PUBLIC_KEY =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE0P43I+jv1i2cc+IHBH3Ht/AbaJ0Bwwtk\n' +
  'x2BDh0PZ7t09Epz55kv+/tJq4n9Lty8GJ5rm9povD3My/dz5Vkd7JA==\n' +
  '-----END PUBLIC KEY-----\n';

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
      getPublicKey: jasmine.createSpy('getPublicKey').and.resolveTo([
        {
          pem: TEST_PUBLIC_KEY,
        },
      ]),
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

  it('should get public key', async () => {
    const expectedPublicKey = createPublicKey(TEST_PUBLIC_KEY);
    mockKmsClient.cryptoKeyVersionPath.and.returnValue('path/to/key/version');

    const publicKey = await signer.getPublicKey();

    expect(publicKey).toEqual(expectedPublicKey);
    expect(mockKmsClient.cryptoKeyVersionPath).toHaveBeenCalledWith(
      'projectId',
      'locationId',
      'keyringId',
      'keyId',
      'versionId',
    );
    expect(mockKmsClient.getPublicKey).toHaveBeenCalledWith({
      name: 'path/to/key/version',
    });
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
});
