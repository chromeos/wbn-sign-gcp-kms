import { GCPWbnSigner } from '../lib/wbn-sign-gcp-kms.js';
import { createPublicKey } from 'crypto';

const samplePublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE0P43I+jv1i2cc+IHBH3Ht/AbaJ0Bwwtk\n' +
  'x2BDh0PZ7t09Epz55kv+/tJq4n9Lty8GJ5rm9povD3My/dz5Vkd7JA==\n' +
  '-----END PUBLIC KEY-----\n';

describe('GCPWbnSigner', () => {
  let signer;
  let mockKmsClient;

  beforeEach(() => {
    mockKmsClient = {
      cryptoKeyVersionPath: jasmine.createSpy('cryptoKeyVersionPath'),
      asymmetricSign: jasmine.createSpy('asymmetricSign').and.resolveTo([{ signature: new Uint8Array([4, 5, 6]) }]),
      getPublicKey: jasmine.createSpy('getPublicKey').and.resolveTo([{
        pem: samplePublicKey
       }]),
    };

    signer = new GCPWbnSigner(
      'projectId',
      'locationId',
      'keyringId',
      'keyId',
      'versionId',
      mockKmsClient
    );
  });

  it('should sign data', async () => {
    const testData = new Uint8Array([1, 2, 3]);
    const expectedSignature = new Uint8Array([4, 5, 6]);

    mockKmsClient.cryptoKeyVersionPath.and.returnValue('path/to/key/version');

    const signature = await signer.sign(testData);

    expect(signature).toEqual(expectedSignature);
    expect(mockKmsClient.cryptoKeyVersionPath).toHaveBeenCalledWith('projectId', 'locationId', 'keyringId', 'keyId', 'versionId');
    expect(mockKmsClient.asymmetricSign).toHaveBeenCalledWith({
      name: 'path/to/key/version',
      digest: {
        sha256: jasmine.any(Buffer),
      },
    });
  });

  it('should throw error when signing fails', async () => {
    mockKmsClient.asymmetricSign.and.rejectWith(new Error('Signing failed'));

    await expectAsync(signer.sign(new Uint8Array())).toBeRejectedWithError('Signing failed');
  });

  it('should throw error when returned invalid object as signature', async () => {
    mockKmsClient.asymmetricSign.and.returnValue([{ not_signature: true }]);

    await expectAsync(signer.sign(new Uint8Array())).toBeRejectedWithError('No signature in response!');
  });

  it('should get public key', async () => {
    const expectedPublicKey = createPublicKey(samplePublicKey);
    mockKmsClient.cryptoKeyVersionPath.and.returnValue('path/to/key/version');

    const publicKey = await signer.getPublicKey();

    expect(publicKey).toEqual(expectedPublicKey);
    expect(mockKmsClient.cryptoKeyVersionPath).toHaveBeenCalledWith('projectId', 'locationId', 'keyringId', 'keyId', 'versionId');
    expect(mockKmsClient.getPublicKey).toHaveBeenCalledWith({ name: 'path/to/key/version' });
  });

  it('should throw error when getting public key fails', async () => {
    mockKmsClient.getPublicKey.and.rejectWith(new Error('Get Public Key failed'));

    await expectAsync(signer.getPublicKey()).toBeRejectedWithError('Get Public Key failed');
  });

  it('should throw error when got unexpected object as public key', async () => {
    mockKmsClient.getPublicKey.and.returnValue([{not_pem: true}]);

    await expectAsync(signer.getPublicKey()).toBeRejectedWithError('No public key in response!');
  });
});
