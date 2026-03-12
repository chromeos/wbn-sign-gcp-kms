import { GCPWbnSigner } from '../lib/wbn-sign-gcp-kms.js';
import { readFile } from 'fs/promises';
import { verify } from 'crypto';

if (process.argv.length < 3) {
  console.error('Usage: npm run test:manual -- <path-to-key-config.json>');
  process.exit(1);
}

const keyConfigPath = process.argv[2];

async function main() {
  try {
    const keyConfigContent = await readFile(keyConfigPath, 'utf-8');
    const keyConfig = JSON.parse(keyConfigContent);

    console.log(`Loaded key config from ${keyConfigPath}`);
    console.log('Key Config:', keyConfig);

    const signer = new GCPWbnSigner(keyConfig);

    const dataToSign = Buffer.from('Hello, World! This is a test for GCPWbnSigner.');
    console.log('Data to sign:', dataToSign.toString());

    console.log('Signing data...');
    const signature = await signer.sign(dataToSign);
    console.log('Signature obtained:', Buffer.from(signature).toString('hex'));

    console.log('Fetching Public Key...');
    const publicKey = await signer.getPublicKey();
    console.log('Public Key obtained.');

    console.log('Verifying signature...');
    const algorithm = publicKey.asymmetricKeyType === 'ed25519' ? undefined : 'sha256';
    const isSignatureValid = verify(algorithm, dataToSign, publicKey, signature);

    if (isSignatureValid) {
      console.log('SUCCESS: Signature is valid.');
    } else {
      console.error('FAILURE: Signature is INVALID.');
      process.exit(1);
    }

  } catch (error) {
    console.error('An error occurred:', error);
    process.exit(1);
  }
}

main();
