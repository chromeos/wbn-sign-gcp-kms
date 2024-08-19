#!/usr/bin/env node
import { GCPWbnSigner } from '../lib/wbn-sign-gcp-kms.cjs'
import * as fs from 'fs';
import * as wbnSign from 'wbn-sign';
import { Command, Option } from 'commander';

const program = new Command();

program
  .option('--key-id-json <key-id-json>', 'The path to a JSON file containing key ID information.', collectKeyIds, [])
  .parse(process.argv);

function collectKeyIds(value, previous) {
  const keyInfo = JSON.parse(fs.readFileSync(value, 'utf-8'));
  previous.push(keyInfo);
  return previous;
}

const options = program.opts();

for (const keyInfo of options.keyIdJson) {
  const { 
    project, 
    location,
    keyring,
    key, 
    version 
  } = keyInfo;
  console.log('For:', keyInfo)
  console.log('Web bundle id:',
    (new wbnSign.WebBundleId(
      await (new GCPWbnSigner(project, location, keyring, key, version))
          .getPublicKey()))
        .serialize())
}
