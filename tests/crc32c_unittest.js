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

import { crc32c, parseCrc32cValue } from '../lib/crc32c.js';

function referenceBitwiseCrc32c(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (0x82f63b78 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

describe('crc32c', () => {
  it('should compute RFC 3720 Appendix B.4 Castagnoli test vectors', () => {
    expect(crc32c(new Uint8Array(0))).toBe(0);
    expect(crc32c(Buffer.from('123456789', 'ascii'))).toBe(0xe3069283);
    expect(crc32c(new Uint8Array(32))).toBe(0x8a9136aa);
    expect(crc32c(new Uint8Array(32).fill(0xff))).toBe(0x62a8ab43);
    expect(crc32c(Uint8Array.from({ length: 32 }, (_, i) => i))).toBe(
      0x46dd794e,
    );
    expect(crc32c(Uint8Array.from({ length: 32 }, (_, i) => 31 - i))).toBe(
      0x113fdb5c,
    );
  });

  it('should match a bitwise Castagnoli reference across pseudo-random inputs', () => {
    let state = 0x12345678;
    const nextByte = () => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state >>> 24;
    };
    for (let i = 0; i < 200; i++) {
      const length = (i * 17) % 257;
      const buf = new Uint8Array(length);
      for (let j = 0; j < length; j++) {
        buf[j] = nextByte();
      }
      expect(crc32c(buf)).toBe(referenceBitwiseCrc32c(buf));
    }
  });
});

describe('parseCrc32cValue', () => {
  it('should parse valid uint32 numbers, decimal strings, and Long-like objects', () => {
    expect(parseCrc32cValue({ value: 0 })).toBe(0);
    expect(parseCrc32cValue({ value: 0xe3069283 })).toBe(0xe3069283);
    expect(parseCrc32cValue({ value: 0xffffffff })).toBe(0xffffffff);
    expect(parseCrc32cValue({ value: '0' })).toBe(0);
    expect(parseCrc32cValue({ value: '3808858755' })).toBe(0xe3069283);
    expect(parseCrc32cValue({ value: '4294967295' })).toBe(0xffffffff);
    expect(parseCrc32cValue({ value: { toString: () => '12345' } })).toBe(
      12345,
    );
  });

  it('should return null for absent, empty, negative, or out-of-range values', () => {
    expect(parseCrc32cValue(undefined)).toBeNull();
    expect(parseCrc32cValue(null)).toBeNull();
    expect(parseCrc32cValue({})).toBeNull();
    expect(parseCrc32cValue({ value: null })).toBeNull();
    expect(parseCrc32cValue({ value: '' })).toBeNull();
    expect(parseCrc32cValue({ value: '   ' })).toBeNull();
    expect(parseCrc32cValue({ value: -1 })).toBeNull();
    expect(parseCrc32cValue({ value: '-1' })).toBeNull();
    expect(parseCrc32cValue({ value: 0x100000000 })).toBeNull();
    expect(parseCrc32cValue({ value: '4294967296' })).toBeNull();
    expect(parseCrc32cValue({ value: 1.5 })).toBeNull();
    expect(parseCrc32cValue({ value: '0x10' })).toBeNull();
    expect(parseCrc32cValue({ value: NaN })).toBeNull();
    expect(parseCrc32cValue({ value: Infinity })).toBeNull();
  });
});
