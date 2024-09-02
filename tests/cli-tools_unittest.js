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

import { getGetIdsArgs, getSignArgs } from '../lib/cli/cli-tools.js';

describe('cli-tools', () => {
  describe('getGetIdsArgs', () => {
    it('should parse key ID JSON file paths from command line arguments', () => {
      const argv = [
        '',
        '',
        '--key-id-json',
        'tests/assets/key1.json',
        '--key-id-json',
        'tests/assets/key2.json',
      ];

      const options = getGetIdsArgs(argv);

      expect(options.keyIdJson).toEqual([
        {
          project: 'project-id',
          location: 'global',
          keyring: 'keyring-id',
          key: 'key-id',
          version: '1',
        },
        {
          project: 'project-id2',
          location: 'us-central1',
          keyring: 'keyring-id2',
          key: 'key-id2',
          version: '2',
        },
      ]);
    });

    it('should fail correctly if key file nonexistent', () => {
      const argv = ['', '', '--key-id-json', 'nonexistent.json'];

      expect(() => getGetIdsArgs(argv)).toThrowError(
        "ENOENT: no such file or directory, open 'nonexistent.json'"
      );
    });

    it('should fail correctly if key file invalid', () => {
      const argv = ['', '', '--key-id-json', 'tests/assets/key_invalid.json'];

      expect(() => getGetIdsArgs(argv)).toThrowError(
        'Unexpected end of JSON input'
      );
    });
  });

  describe('getSignArgs', () => {
    it('should parse all required and optional arguments from command line', () => {
      const argv = [
        '',
        '',
        '--input',
        'path/to/input.wbn',
        '--output',
        'path/to/output.swbn',
        '--web-bundle-id',
        'my-web-bundle',
        '--key-id-json',
        'tests/assets/key1.json',
        '--key-id-json',
        'tests/assets/key2.json',
      ];

      const options = getSignArgs(argv);

      expect(options.input).toBe('path/to/input.wbn');
      expect(options.output).toBe('path/to/output.swbn');
      expect(options.webBundleId).toBe('my-web-bundle');
      expect(options.keyIdJson).toEqual([
        {
          project: 'project-id',
          location: 'global',
          keyring: 'keyring-id',
          key: 'key-id',
          version: '1',
        },
        {
          project: 'project-id2',
          location: 'us-central1',
          keyring: 'keyring-id2',
          key: 'key-id2',
          version: '2',
        },
      ]);
    });
  });
});
