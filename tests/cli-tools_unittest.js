import { getDumpIdArgs, getSignArgs } from '../lib/cli/cli-tools.js';

describe('cli-tools', () => {
  describe('getDumpIdArgs', () => {
    it('should parse key ID JSON file paths from command line arguments', () => {
      const argv = [
        '',
        '',
        '--key-id-json',
        'tests/assets/key1.json',
        '--key-id-json',
        'tests/assets/key2.json',
      ];

      const options = getDumpIdArgs(argv);

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
