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

import { Command, InvalidArgumentError, OptionValues } from 'commander';
import { readFileSync, writeFileSync } from 'fs';
import {
  GCPKeyInfo,
  getWebBundleIds,
  signBundle,
  validateKeyInfo,
} from '../wbn-sign-gcp-kms.js';

/**
 * Handlers invoked by {@link wbnGcpKmpSubcommands}.
 */
export interface SubcommandHandlers {
  sign: (options: OptionValues) => Promise<void>;
  getIds: (options: OptionValues) => Promise<void>;
}

/**
 * @param {string} filename The path to the JSON file containing key ID information.
 * @param {GCPKeyInfo[]} previous The array to append the key ID information to.
 * @returns {GCPKeyInfo[]} The array with the key ID information appended.
 */
function collectKeyIds(filename: string, previous: GCPKeyInfo[]): GCPKeyInfo[] {
  try {
    const fileContents: string = readFileSync(filename, 'utf-8');
    const keyInfo = validateKeyInfo(JSON.parse(fileContents));
    previous.push(keyInfo);
  } catch (e) {
    throw new InvalidArgumentError(e instanceof Error ? e.message : String(e));
  }
  return previous;
}

function configureGetIdsCommand(command: Command): Command {
  return command.option(
    '-k, --key-id-json <key-id-json>',
    'The path to a JSON file containing key ID information.',
    collectKeyIds,
    [],
  );
}

function configureSignCommand(command: Command): Command {
  return command
    .requiredOption(
      '-i, --input <input-file>',
      'The path to the input web bundle file.',
    )
    .requiredOption(
      '-o, --output <output-file>',
      'The path to save the signed web bundle file.',
    )
    .option(
      '-w, --web-bundle-id <bundle-id>',
      'Signed Web Bundle ID associated with the bundle.',
      undefined,
    )
    .option(
      '-k, --key-id-json <key-id-json>',
      'The path to a JSON file containing key ID information.',
      collectKeyIds,
      [],
    );
}

/**
 * Creates the standalone Commander command for `get-ids`.
 */
export function createGetIdsCommand(): Command {
  return configureGetIdsCommand(new Command());
}

/**
 * Creates the standalone Commander command for `sign`.
 */
export function createSignCommand(): Command {
  return configureSignCommand(new Command());
}

/**
 * Executes the sign command with parsed options.
 */
export async function runSign(options: OptionValues): Promise<void> {
  const { input, output, webBundleId, keyIdJson } = options;
  const webBundle = readFileSync(input);
  const signedWebBundle = await signBundle(webBundle, keyIdJson, webBundleId);
  writeFileSync(output, signedWebBundle);
}

/**
 * Executes the get-ids command with parsed options.
 */
export async function runGetIds(options: OptionValues): Promise<void> {
  console.log(await getWebBundleIds(options.keyIdJson));
}

/**
 * Parses the command line arguments for the dump-id command.
 * @param {string[]} argv The command line arguments.
 * @returns {OptionValues} The parsed command line arguments.
 */
export function getGetIdsArgs(argv: string[]): OptionValues {
  return createGetIdsCommand().parse(argv).opts();
}

/**
 * Parses the command line arguments for the sign command.
 * @param {string[]} argv The command line arguments.
 * @returns {OptionValues} The parsed command line arguments.
 */
export function getSignArgs(argv: string[]): OptionValues {
  return createSignCommand().parse(argv).opts();
}

/**
 * Builds the root `wbn-gcp-kms` Commander program with in-process `sign` and
 * `get-ids` subcommands.
 */
export function createProgram(
  handlers: SubcommandHandlers = { sign: runSign, getIds: runGetIds },
): Command {
  const program = new Command();
  program.name('wbn-gcp-kms');
  configureSignCommand(
    program.command('sign').description('Sign a web bundle using GCP KMS.'),
  ).action(async (options: OptionValues) => {
    await handlers.sign(options);
  });
  configureGetIdsCommand(
    program
      .command('get-ids')
      .description('Get the web bundle IDs for a set of key IDs.'),
  ).action(async (options: OptionValues) => {
    await handlers.getIds(options);
  });
  return program;
}

/**
 * Main function for the wbn-gcp-kms command. Directs to subcommands `sign` and `get-ids`.
 */
export async function wbnGcpKmpSubcommands(
  argv: string[],
  handlers: SubcommandHandlers = { sign: runSign, getIds: runGetIds },
): Promise<void> {
  await createProgram(handlers).parseAsync(argv);
}
