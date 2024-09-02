# Signing web bundles using GCP KMS API

This is a Node.js module for signing
[Web Bundles](https://wpack-wg.github.io/bundled-responses/draft-ietf-wpack-bundled-responses.html)
using [wbn-sign](https://github.com/WICG/webpackage/tree/main/js/sign) with
[GCP KMS API](https://cloud.google.com/kms/docs/create-validate-signatures).

## Usage

### Lib

You can supply the `GCPWbnSigner` class to `wbnSign.IntegrityBlockSigner` from
the `wbn-sign` NPM package like this:

```js
import { GCPWbnSigner } from 'wbn-sign-gcp-kms';

...

const { signedWebBundle } = await new wbnSign.IntegrityBlockSigner(
  true,
  webBundle,
  webBundleId,
  [
    new GCPWbnSigner({
      project: projectId,
      location: locationId,
      keyring: keyringId,
      key: keyId,
      version: versionId
    })
  ]
).sign();
```

There's also a shortcut to that, `signBundle`:

```js
import { signBundle } from 'wbn-sign-gcp-kms';

...

const signedWebBundle = await signBundle(
  webBundle,
  webBundleId,
  [
    {
      project: projectId,
      location: locationId,
      keyring: keyringId,
      key: keyId,
      version: versionId
    }
  ]
);
```

Provided that the key path is correct and you are correctly authenticated for
the purpose of
[GCP KMS Node.js API](https://cloud.google.com/nodejs/docs/reference/kms/latest),
this will give you the signed web bundle.

You can also get the web bundle IDs of your keys using a helper function:

```js
import { getWebBundleIds } from 'wbn-sign-gcp-kms';

...

const keyIdsWithBundleIds = await getWebBundleIds(
  [
    {
      project: projectId,
      location: locationId,
      keyring: keyringId,
      key: keyId,
      version: versionId
    },
    {
      project: projectId2,
      location: locationId2,
      keyring: keyringId2,
      key: keyId2,
      version: versionId2
    }
  ]
)
```

This will return `GCPKeyInfoWithBundleId[]` for the provided keys.

### CLI

Example of signing:

```bash
$ wbn-gcp-kms sign \
  --key-id-json ./key1.json \
  --key-id-json ./key2.json \
  --web-bundle-id ao6qlxy53numov53l37w3vcvtpckzhmbvhoqtqs7g6enzlkqdya5waacai \
  --input webbundle.wbn \
  --output webbundle.swbn
```

Example of dumping bundle IDs:

```bash
$ wbn-gcp-kms get-ids --key-id-json ./key1.json --key-id-json ./key2.json
[
  {
    project: 'project-1',
    location: 'global',
    keyring: 'keyring-1',
    key: 'key-1',
    version: '1',
    webBundleId: 'ao6qlxy53numov53l37w3vcvtpckzhmbvhoqtqs7g6enzlkqdya5waacai'
  },
  {
    project: 'project-2',
    location: 'us-central1',
    keyring: 'keyring-2',
    key: 'key-2',
    version: '2',
    webBundleId: 'apoxa7f2rif64q7nzkp5l5cgdhkusxwzl4fjl4m6vkbbpbptpdpcoaacai'
  }
]
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
