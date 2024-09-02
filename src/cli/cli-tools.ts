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

import { Command, OptionValues } from 'commander';
import { readFileSync } from 'fs';
import { signMain } from './wbn-sign-gcp-kms-cli.js';
import { getIdsMain } from './wbn-get-ids-gcp-kms-cli.js';

/**
 * @param {string} filename The path to the JSON file containing key ID information.
 * @param {any[]} previous The array to append the key ID information to.
 * @returns {any[]} The array with the key ID information appended.
 */
function collectKeyIds(filename: string, previous: any[]) {
  try {
    const fileContents: string = readFileSync(filename, 'utf-8');
    const keyInfo = JSON.parse(fileContents);
    previous.push(keyInfo);
  } catch (e) {
    console.error(`Could not parse or open key ID JSON file: ${filename}`);
    throw e;
  }
  return previous;
}

/**
 * Parses the command line arguments for the dump-id command.
 * @param {string[]} argv The command line arguments.
 * @returns {OptionValues} The parsed command line arguments.
 */
export function getGetIdsArgs(argv: string[]): OptionValues {
  const program = new Command();
  return program
    .option(
      '-k, --key-id-json <key-id-json>',
      'The path to a JSON file containing key ID information.',
      collectKeyIds,
      []
    )
    .parse(argv)
    .opts();
}

/**
 * Parses the command line arguments for the sign command.
 * @param {string[]} argv The command line arguments.
 * @returns {OptionValues} The parsed command line arguments.
 */
export function getSignArgs(argv: string[]): OptionValues {
  const program = new Command();
  return program
    .requiredOption(
      '-i, --input <input-file>',
      'The path to the input web bundle file.'
    )
    .requiredOption(
      '-o, --output <output-file>',
      'The path to save the signed web bundle file.'
    )
    .option(
      '-w, --web-bundle-id <bundle-id>',
      'Signed Web Bundle ID associated with the bundle.',
      undefined
    )
    .option(
      '-k, --key-id-json <key-id-json>',
      'The path to a JSON file containing key ID information.',
      collectKeyIds,
      []
    )
    .parse(argv)
    .opts();
}

/**
 * Main function for the wbn-gcp-kms command. Directs to subcommands `sign` and `get-ids`.
 */
export function wbnGcpKmpSubcommands(argv: string[]) {
  const program = new Command();
  program.name('wbn-gcp-kms');
  program
    .command('sign', 'Sign a web bundle using GCP KMS.')
    .command('get-ids', 'Get the web bundle IDs for a set of key IDs.')
    .parse(argv);
}
