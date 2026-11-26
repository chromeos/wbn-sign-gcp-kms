/**
 * Copyright 2026 Google LLC
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

import {
  GCPWbnSigner,
  getWebBundleIds,
  signBundle,
  validateKeyInfo,
} from 'wbn-sign-gcp-kms';
import type { GCPKeyInfo, GCPKeyInfoWithBundleId } from 'wbn-sign-gcp-kms';

const keyInfo: GCPKeyInfo = validateKeyInfo({
  project: 'project',
  location: 'global',
  keyring: 'keyring',
  key: 'key',
  version: '1',
});
const signer = new GCPWbnSigner(keyInfo);
const signature: Promise<Uint8Array> = signer.sign(new Uint8Array());
const signed: Promise<Uint8Array> = signBundle(new Uint8Array(), [keyInfo]);
const ids: Promise<GCPKeyInfoWithBundleId[]> = getWebBundleIds([keyInfo]);

// @ts-expect-error GCPKeyInfo requires all five fields.
new GCPWbnSigner({ project: 'project' });

export { signature, signed, ids };
