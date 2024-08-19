# Signing with Integrity Block

This is a Node.js module for signing
[Web Bundles](https://wpack-wg.github.io/bundled-responses/draft-ietf-wpack-bundled-responses.html) using [wbn-sign](https://github.com/WICG/webpackage/tree/main/js/sign)
with [GCP KMS API](https://cloud.google.com/kms/docs/create-validate-signatures).

The CLI tool `wbn-sign-gcp-kms` takes an existing bundle file and info as to where in GCP is your `EC_SIGN_P256_SHA256` key located, then saves the signed web bundle in specified `.swbn` file.

## Usage

Example:
```
wbn-sign-gcp-kms \
  --project project-id \
  --location global \
  --keyring default-keyring \
  --key default-key \
  --version 1 \
  --input webbundle.wbn \
  --output webbundle.swbn
```
