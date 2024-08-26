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
