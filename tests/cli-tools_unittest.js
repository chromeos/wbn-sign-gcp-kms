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

import { spawnSync } from 'child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { pathToFileURL } from 'url';
import {
  createGetIdsCommand,
  createProgram,
  getGetIdsArgs,
  getSignArgs,
  wbnGcpKmpSubcommands,
} from '../lib/cli/cli-tools.js';

function parseGetIdsWithExitOverride(argv) {
  return createGetIdsCommand()
    .exitOverride()
    .configureOutput({ writeErr: () => {}, writeOut: () => {} })
    .parse(argv)
    .opts();
}

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

    it('should fail with InvalidArgumentError if key file nonexistent', () => {
      const argv = ['', '', '--key-id-json', 'nonexistent.json'];

      expect(() => parseGetIdsWithExitOverride(argv)).toThrowError(
        /ENOENT: no such file or directory, open 'nonexistent\.json'/,
      );
    });

    it('should fail with InvalidArgumentError if key file invalid', () => {
      const argv = ['', '', '--key-id-json', 'tests/assets/key_invalid.json'];

      expect(() => parseGetIdsWithExitOverride(argv)).toThrowError(
        /Unexpected end of JSON input/,
      );
    });

    it('should fail with InvalidArgumentError if key file contains path traversal', () => {
      const argv = ['', '', '--key-id-json', 'tests/assets/key_traversal.json'];

      expect(() => parseGetIdsWithExitOverride(argv)).toThrowError(
        /Invalid GCPKeyInfo\.version/,
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

  describe('createProgram and wbnGcpKmpSubcommands', () => {
    it('should dispatch sign subcommand in-process', async () => {
      const handlers = {
        sign: jasmine.createSpy('sign').and.resolveTo(),
        getIds: jasmine.createSpy('getIds').and.resolveTo(),
      };

      await wbnGcpKmpSubcommands(
        [
          'node',
          '/nonexistent/relocated/wbn-gcp-kms.js',
          'sign',
          '--input',
          'in.wbn',
          '--output',
          'out.swbn',
          '--web-bundle-id',
          'bundle-id',
          '--key-id-json',
          'tests/assets/key1.json',
        ],
        handlers,
      );

      expect(handlers.sign).toHaveBeenCalledOnceWith({
        input: 'in.wbn',
        output: 'out.swbn',
        webBundleId: 'bundle-id',
        keyIdJson: [
          {
            project: 'project-id',
            location: 'global',
            keyring: 'keyring-id',
            key: 'key-id',
            version: '1',
          },
        ],
      });
      expect(handlers.getIds).not.toHaveBeenCalled();
    });

    it('should dispatch get-ids subcommand in-process', async () => {
      const handlers = {
        sign: jasmine.createSpy('sign').and.resolveTo(),
        getIds: jasmine.createSpy('getIds').and.resolveTo(),
      };

      await wbnGcpKmpSubcommands(
        [
          'node',
          '/nonexistent/relocated/wbn-gcp-kms.js',
          'get-ids',
          '--key-id-json',
          'tests/assets/key2.json',
        ],
        handlers,
      );

      expect(handlers.getIds).toHaveBeenCalledOnceWith({
        keyIdJson: [
          {
            project: 'project-id2',
            location: 'us-central1',
            keyring: 'keyring-id2',
            key: 'key-id2',
            version: '2',
          },
        ],
      });
      expect(handlers.sign).not.toHaveBeenCalled();
    });

    it('should render root and subcommand help cleanly', async () => {
      let stdout = '';
      const program = createProgram()
        .exitOverride()
        .configureOutput({
          writeOut: (str) => {
            stdout += str;
          },
          writeErr: () => {},
        });

      await expectAsync(
        program.parseAsync(['node', 'wbn-gcp-kms', '--help']),
      ).toBeRejectedWith(
        jasmine.objectContaining({
          code: 'commander.helpDisplayed',
          exitCode: 0,
        }),
      );
      expect(stdout).toContain('sign [options]');
      expect(stdout).toContain('get-ids [options]');

      let subHelp = '';
      const subProgram = createProgram()
        .exitOverride()
        .configureOutput({
          writeOut: (str) => {
            subHelp += str;
          },
          writeErr: () => {},
        });
      subProgram.commands.forEach((cmd) =>
        cmd.exitOverride().configureOutput({
          writeOut: (str) => {
            subHelp += str;
          },
          writeErr: () => {},
        }),
      );

      await expectAsync(
        subProgram.parseAsync(['node', 'wbn-gcp-kms', 'sign', '--help']),
      ).toBeRejectedWith(
        jasmine.objectContaining({
          code: 'commander.helpDisplayed',
          exitCode: 0,
        }),
      );
      expect(subHelp).toContain('--input <input-file>');
      expect(subHelp).toContain('--output <output-file>');
      expect(subHelp).toContain('--key-id-json <key-id-json>');
    });

    it('should reject unknown subcommands and missing required options', async () => {
      const configureSilent = (cmd) => {
        cmd.exitOverride().configureOutput({
          writeOut: () => {},
          writeErr: () => {},
        });
        cmd.commands.forEach(configureSilent);
        return cmd;
      };

      await expectAsync(
        configureSilent(createProgram()).parseAsync([
          'node',
          'wbn-gcp-kms',
          'unknown-cmd',
        ]),
      ).toBeRejectedWith(
        jasmine.objectContaining({
          code: 'commander.unknownCommand',
          exitCode: 1,
        }),
      );

      await expectAsync(
        configureSilent(createProgram()).parseAsync([
          'node',
          'wbn-gcp-kms',
          'sign',
          '-o',
          'out.swbn',
        ]),
      ).toBeRejectedWith(
        jasmine.objectContaining({
          code: 'commander.missingMandatoryOptionValue',
          exitCode: 1,
        }),
      );
    });

    it('should propagate handler rejections', async () => {
      const handlers = {
        sign: jasmine.createSpy('sign').and.rejectWith(new Error('KMS failed')),
        getIds: jasmine.createSpy('getIds').and.resolveTo(),
      };

      await expectAsync(
        createProgram(handlers).parseAsync([
          'node',
          'wbn-gcp-kms',
          'sign',
          '-i',
          'in.wbn',
          '-o',
          'out.swbn',
          '-k',
          'tests/assets/key1.json',
        ]),
      ).toBeRejectedWithError('KMS failed');
    });

    it('should not spawn a PATH-resolved wbn-gcp-kms-sign binary when relocated', () => {
      const workDir = mkdtempSync(join(tmpdir(), 'wbn-gcp-kms-test-'));
      try {
        const hijackDir = join(workDir, 'hijack');
        const stageDir = join(workDir, 'stage');
        mkdirSync(hijackDir);
        mkdirSync(stageDir);

        const markerFile = join(workDir, 'hijacked-marker');
        const planted = join(hijackDir, 'wbn-gcp-kms-sign');
        writeFileSync(
          planted,
          `#!/bin/sh\necho hijacked > "${markerFile}"\nexit 99\n`,
        );
        chmodSync(planted, 0o755);

        const cliToolsUrl = pathToFileURL(resolve('lib/cli/cli-tools.js')).href;
        const stagedEntry = join(stageDir, 'wbn-gcp-kms.mjs');
        writeFileSync(
          stagedEntry,
          `import { wbnGcpKmpSubcommands } from ${JSON.stringify(cliToolsUrl)};\n` +
            `await wbnGcpKmpSubcommands(process.argv);\n`,
        );

        const result = spawnSync(
          process.execPath,
          [
            stagedEntry,
            'sign',
            '-i',
            'in.wbn',
            '-o',
            'out.swbn',
            '-k',
            'tests/assets/key_traversal.json',
          ],
          {
            encoding: 'utf8',
            env: {
              ...process.env,
              PATH: `${hijackDir}:${process.env.PATH ?? ''}`,
            },
          },
        );

        expect(existsSync(markerFile)).toBeFalse();
        expect(result.status).toBe(1);
        expect(result.stderr).toContain('Invalid GCPKeyInfo.version');
        expect(result.stderr).not.toContain('at collectKeyIds');
      } finally {
        rmSync(workDir, { recursive: true, force: true });
      }
    });
  });
});
