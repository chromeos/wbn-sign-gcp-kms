# Signing web bundles using GCP KMS API

This is a Node.js module for signing
[Web Bundles](https://wpack-wg.github.io/bundled-responses/draft-ietf-wpack-bundled-responses.html)
using [wbn-sign](https://github.com/WICG/webpackage/tree/main/js/sign) with
[GCP KMS API](https://cloud.google.com/kms/docs/create-validate-signatures).

## Usage

### Lib

You can supply the `GCPWbnSigner` class to `wbnSign.IntegrityBlockSigner` from the `wbn-sign` NPM package like this:

```js
import { GCPWbnSigner } from 'wbn-sign-gcp-kms';

...

const { signedWebBundle } = await new wbnSign.IntegrityBlockSigner(
  true,
  webBundle,
  webBundleId,
  [new GCPWbnSigner(projectId, locationId, keyringId, keyId, versionId)]
).sign();
```
Provided that the key path is correct and you are correctly authenticated for the purpose of [GCP KMS Node.js API](https://cloud.google.com/nodejs/docs/reference/kms/latest), this will give you the signed web bundle.

### CLI

Example of signing:

```bash
$ wbn-sign-gcp-kms \
  --key-id-json ./key1.json \
  --key-id-json ./key2.json \
  --web-bundle-id ao6qlxy53numov53l37w3vcvtpckzhmbvhoqtqs7g6enzlkqdya5waacai \
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
