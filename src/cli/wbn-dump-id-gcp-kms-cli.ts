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

import { GCPWbnSigner } from '../wbn-sign-gcp-kms.js';
import * as wbnSign from 'wbn-sign';
import { getDumpIdArgs } from './cli-tools.js';

export async function dumpIdMain() {
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
}
