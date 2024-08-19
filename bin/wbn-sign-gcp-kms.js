#!/usr/bin/env node
import { GCPWbnSigner } from '../lib/wbn-sign-gcp-kms.cjs'
import * as fs from 'fs';
import * as wbnSign from 'wbn-sign';
import { Command, Option } from 'commander';

const program = new Command();

program
  .requiredOption('--input <input-file>', 'The path to the input web bundle file.')
  .requiredOption('--output <output-file>', 'The path to save the signed web bundle file.')
  .requiredOption('--web-bundle-id <bundle-id>', 'Signed Web Bundle ID associated with the bundle.')
  .option('--key-id-json <key-id-json>', 'The path to a JSON file containing key ID information.', collectKeyIds, [])
  .parse(process.argv);

function collectKeyIds(value, previous) {
  const keyInfo = JSON.parse(fs.readFileSync(value, 'utf-8'));
  previous.push(keyInfo);
  return previous;
}

const options = program.opts();

const { 
  input, 
  output,
  webBundleId,
  keyIdJson 
} = options;

const webBundle = fs.readFileSync(input);

const signers = keyIdJson.map(keyInfo => {
  const { 
    project, 
    location,
    keyring,
    key, 
    version 
  } = keyInfo;
  return new GCPWbnSigner(project, location, keyring, key, version);
});

const { signedWebBundle } = await new wbnSign.IntegrityBlockSigner(
  true,
  webBundle,
  webBundleId,
  signers
).sign();

fs.writeFileSync(output, signedWebBundle);
