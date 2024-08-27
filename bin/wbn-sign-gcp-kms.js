#!/usr/bin/env node
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
  webBundle,
  webBundleId,
  signers
).sign();

fs.writeFileSync(output, signedWebBundle);
