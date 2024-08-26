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

function collectKeyIds(value: string, previous: any[]) {
  const keyInfo = JSON.parse(readFileSync(value, 'utf-8'));
  previous.push(keyInfo);
  return previous;
}

export function getDumpIdArgs(argv: string[]): OptionValues {
  const program = new Command();
  return program
    .option(
      '--key-id-json <key-id-json>',
      'The path to a JSON file containing key ID information.',
      collectKeyIds,
      []
    )
    .parse(argv)
    .opts();
}

export function getSignArgs(argv: string[]): OptionValues {
  const program = new Command();
  return program
    .requiredOption(
      '--input <input-file>',
      'The path to the input web bundle file.'
    )
    .requiredOption(
      '--output <output-file>',
      'The path to save the signed web bundle file.'
    )
    .requiredOption(
      '--web-bundle-id <bundle-id>',
      'Signed Web Bundle ID associated with the bundle.'
    )
    .option(
      '--key-id-json <key-id-json>',
      'The path to a JSON file containing key ID information.',
      collectKeyIds,
      []
    )
    .parse(argv)
    .opts();
}
