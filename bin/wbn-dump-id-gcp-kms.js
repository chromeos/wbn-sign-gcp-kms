#!/usr/bin/env node
import { GCPWbnSigner } from '../lib/wbn-sign-gcp-kms.cjs';
import * as wbnSign from 'wbn-sign';
import { getDumpIdArgs } from '../lib/cli/cli-tools.js';

for (const keyInfo of getDumpIdArgs(process.argv).keyIdJson) {
  const { project, location, keyring, key, version } = keyInfo;
  console.log('For:', keyInfo);
  console.log(
    'Web bundle id:',
    new wbnSign.WebBundleId(
      await new GCPWbnSigner(
        project,
        location,
        keyring,
        key,
        version
      ).getPublicKey()
    ).serialize()
  );
}
