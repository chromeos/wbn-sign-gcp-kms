#!/usr/bin/env node
import { GCPWbnSigner } from '../lib/wbn-sign-gcp-kms.cjs'
import * as fs from 'fs';
import * as wbnSign from 'wbn-sign';
import { Command, Option } from 'commander';

const program = new Command();

program
  .requiredOption('--project <project-id>', 'Your Google Cloud project ID')
  .requiredOption('--location <location>', 'The location of the keyring.')
  .requiredOption('--keyring <keyring-name>', 'The name of the Cloud KMS keyring')
  .requiredOption('--key <key-name>', 'The name of the Cloud KMS key')
  .requiredOption('--version <key-version>', 'The version of the Cloud KMS key')
  .requiredOption('--input <input-file>', 'The path to the input web bundle file')
  .requiredOption('--output <output-file>', 'The path to save the signed web bundle file')
  .parse(process.argv);

const options = program.opts();

const { 
  project, 
  location,
  keyring,
  key, 
  version, 
  input, 
  output 
} = options;


const webBundle = fs.readFileSync(input);
const signer = new GCPWbnSigner(project, location, keyring, key, version)
const bundleId = (new wbnSign.WebBundleId(await signer.getPublicKey())).serialize();

const { signedWebBundle } = await new wbnSign.IntegrityBlockSigner(
  true,
  webBundle,
  bundleId,
  [signer]
).sign();

fs.writeFileSync(output, signedWebBundle);
