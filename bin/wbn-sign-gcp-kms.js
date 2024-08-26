#!/usr/bin/env node
import { GCPWbnSigner } from '../lib/wbn-sign-gcp-kms.cjs';
import * as fs from 'fs';
import * as wbnSign from 'wbn-sign';
import { getSignArgs } from '../lib/cli/cli-tools.js';

const { input, output, webBundleId, keyIdJson } = getSignArgs(process.argv);

const webBundle = fs.readFileSync(input);

const signers = keyIdJson.map((keyInfo) => {
  const { project, location, keyring, key, version } = keyInfo;
  return new GCPWbnSigner(project, location, keyring, key, version);
});

const { signedWebBundle } = await new wbnSign.IntegrityBlockSigner(
  true,
  webBundle,
  webBundleId,
  signers
).sign();

fs.writeFileSync(output, signedWebBundle);
