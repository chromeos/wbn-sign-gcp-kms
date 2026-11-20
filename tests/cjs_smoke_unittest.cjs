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

const cjs = require('../lib/wbn-sign-gcp-kms.cjs');

describe('CJS bundle smoke test', () => {
  it('should export the public API and validate key info', () => {
    expect(typeof cjs.GCPWbnSigner).toBe('function');
    expect(typeof cjs.signBundle).toBe('function');
    expect(typeof cjs.getWebBundleIds).toBe('function');
    expect(typeof cjs.validateKeyInfo).toBe('function');

    expect(
      cjs.validateKeyInfo({
        project: 'google.com:my-project',
        location: 'global',
        keyring: 'ring',
        key: 'key',
        version: '1',
      }),
    ).toEqual({
      project: 'google.com:my-project',
      location: 'global',
      keyring: 'ring',
      key: 'key',
      version: '1',
    });

    expect(() =>
      cjs.validateKeyInfo({
        project: 'proj',
        location: 'global',
        keyring: 'ring',
        key: 'key',
        version: '1/../cryptoKeyVersions/999',
      }),
    ).toThrowError(/Invalid GCPKeyInfo\.version/);
  });
});
