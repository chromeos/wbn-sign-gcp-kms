# Signing with Integrity Block

This is a Node.js module for signing
[Web Bundles](https://wpack-wg.github.io/bundled-responses/draft-ietf-wpack-bundled-responses.html) using [wbn-sign](https://github.com/WICG/webpackage/tree/main/js/sign)
with [GCP KMS API](https://cloud.google.com/kms/docs/create-validate-signatures).

The CLI tool `wbn-sign-gcp-kms` takes an existing bundle file and info as to where in GCP is your `EC_SIGN_P256_SHA256` key located, then saves the signed web bundle in specified `.swbn` file.

## Usage

Example of signing:
```bash
$ wbn-sign-gcp-kms \
  --key-id-json ./key1.json \
  --key-id-json ./key2.json \
  --input webbundle.wbn \
  --output webbundle.swbn
```

Example of dumping bundle IDs:
```bash
$ wbn-dump-id-gcp-kms --key-id-json ./key1.json --key-id-json ./key2.json
For: {
  project: 'project-id',
  location: 'global',
  keyring: 'keyring-id',
  key: 'key-id',
  version: '1'
}
Web bundle id: ao6qlxy53numov53l37w3vcvtpckzhmbvhoqtqs7g6enzlkqdya5waacai
For: {
  project: 'project-id',
  location: 'global',
  keyring: 'keyring-id',
  key: 'key-id',
  version: '2'
}
Web bundle id: apoxa7f2rif64q7nzkp5l5cgdhkusxwzl4fjl4m6vkbbpbptpdpcoaacai
```

Sample JSON identifying a key:

```json
{
  "project": "project-id",
  "location": "global",
  "keyring": "keyring-id",
  "key": "key-id",
  "version": "1"
}
```
