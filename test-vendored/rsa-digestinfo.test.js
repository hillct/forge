'use strict';
// Regression tests for the vendored fork (GHSA-86w9-cpqp-85rv). See VENDORED.md.
const test = require('node:test');
const assert = require('node:assert');
const forge = require('..');

const { asn1 } = forge;
const { BigInteger } = forge.jsbn;
const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
const MSG = 'hello';

const digest = (alg = 'sha256') => {
  const md = forge.md[alg].create();
  md.update(MSG);
  return md.digest().getBytes();
};
const node = (type, constructed, value) => asn1.create(asn1.Class.UNIVERSAL, type, constructed, value);

// Textbook private-key operation over a hand-built EMSA-PKCS1-v1_5 block, so the
// DigestAlgorithm contents are fully under test control.
const sign = ({ alg = 'sha256', algExtras = [], nullParams = true, digestBytes } = {}) => {
  const children = [node(asn1.Type.OID, false, asn1.oidToDer(forge.oids[alg]).getBytes())];
  if (nullParams) children.push(node(asn1.Type.NULL, false, ''));
  children.push(...algExtras);
  const info = node(asn1.Type.SEQUENCE, true, [
    node(asn1.Type.SEQUENCE, true, children),
    node(asn1.Type.OCTETSTRING, false, digestBytes === undefined ? digest(alg) : digestBytes),
  ]);
  const der = asn1.toDer(info).getBytes();
  const k = Math.ceil(privateKey.n.bitLength() / 8);
  const em = '\x00\x01' + '\xff'.repeat(k - der.length - 3) + '\x00' + der;
  let hex = new BigInteger(forge.util.bytesToHex(em), 16).modPow(privateKey.d, privateKey.n).toString(16);
  while (hex.length < k * 2) hex = '0' + hex;
  return forge.util.hexToBytes(hex);
};

test('a normal signature verifies (library signer and hand-built, with NULL params)', () => {
  const md = forge.md.sha256.create();
  md.update(MSG);
  assert.strictEqual(publicKey.verify(digest(), privateKey.sign(md)), true);
  assert.strictEqual(publicKey.verify(digest(), sign()), true);
});

test('a signature without the optional NULL parameters verifies', () => {
  assert.strictEqual(publicKey.verify(digest(), sign({ nullParams: false })), true);
});

test('trailing garbage inside DigestAlgorithm is rejected (the advisory)', () => {
  const extra = node(asn1.Type.OCTETSTRING, false, 'garbage');
  assert.throws(() => publicKey.verify(digest(), sign({ algExtras: [extra] })), /valid RSASSA-PKCS1-v1_5 DigestInfo/);
  assert.throws(() => publicKey.verify(digest(), sign({ nullParams: false, algExtras: [extra, extra] })), /DigestInfo/);
});

test('a wrong digest still fails verification', () => {
  assert.strictEqual(publicKey.verify(digest('sha1'), sign({ alg: 'sha1', digestBytes: 'x'.repeat(20) })), false);
});

test('other hash algorithms still verify', () => {
  for (const alg of ['sha1', 'sha384', 'sha512']) {
    assert.strictEqual(publicKey.verify(digest(alg), sign({ alg })), true, alg);
  }
});
