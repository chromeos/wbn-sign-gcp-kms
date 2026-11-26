/**
 * Copyright 2026 Google LLC
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

import type { protos } from '@google-cloud/kms';

const CASTAGNOLI_POLY = 0x82f63b78;
const MAX_UINT32 = 0xffffffff;

const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let crc = i;
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (CASTAGNOLI_POLY & -(crc & 1));
    }
    table[i] = crc >>> 0;
  }
  return table;
})();

/**
 * Computes the Castagnoli CRC32C checksum of the given bytes.
 */
export function crc32c(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32C_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Parses a protobuf Int64Value CRC32C field into an unsigned 32-bit integer,
 * or returns null if the field is absent or not a valid uint32.
 *
 * Fails closed when a wrapper object is present with an unset `value` rather
 * than coercing `null`/`undefined` to `0`.
 */
export function parseCrc32cValue(
  crcField: protos.google.protobuf.IInt64Value | null | undefined,
): number | null {
  const raw = crcField?.value;
  if (raw == null) {
    return null;
  }
  if (typeof raw === 'number') {
    return Number.isInteger(raw) && raw >= 0 && raw <= MAX_UINT32 ? raw : null;
  }
  const str = typeof raw === 'string' ? raw : raw.toString();
  if (!/^\d+$/.test(str)) {
    return null;
  }
  const parsed = Number(str);
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= MAX_UINT32
    ? parsed
    : null;
}
