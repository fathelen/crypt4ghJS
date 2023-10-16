/* eslint no-undef: */
const index = require('crypt4gh_js')

const pubkey = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nGER04WfJXzPHiCWe94CHlMY6sp6zwWpAehA0MMHjdVQ=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const seckey = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAg4BW6LpwKHBQN0MCZgjPtDafcGbN5wRmUSrIwEcN4te0=\n-----END CRYPT4GH PRIVATE KEY-----\n'
const pubkeyPass = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nvHrVpBpFLpX/OquK2Ze4Mfzb8aVrn05XmTgT4ymVwzE=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const seckeyPass = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAMHZyZm0wb3JrM2E5d2QyeQARY2hhY2hhMjBfcG9seTEzMDUAPHUyY2lhbDQ1dWZydxzqFWikrPHQc6dKqWySS59BoMAe1L0FRmBXnwPd80N4fJBJS5f+vnmlA+JZ8qCpow==\n-----END CRYPT4GH PRIVATE KEY-----\n'

// test key generation without password
test('generate secret/ public key pair without password', async () => {
  const encKeys = await index.keygen.keygen('')
  expect(encKeys).toBeInstanceOf(Array)
  expect(typeof (encKeys[0])).toEqual('string')
  expect(typeof (encKeys[1])).toEqual('string')
  expect(encKeys[0]).toMatch(/-----BEGIN CRYPT4GH PRIVATE KEY-----/)
  expect(encKeys[0]).toMatch(/-----END CRYPT4GH PRIVATE KEY-----/)
  expect(encKeys[1]).toMatch(/-----BEGIN CRYPT4GH PUBLIC KEY-----/)
  expect(encKeys[1]).toMatch(/-----END CRYPT4GH PUBLIC KEY-----/)
})

// test key generation with password
test('generate secret/ public key pair with password', async () => {
  const encKeys = await index.keygen.keygen('password')
  expect(encKeys).toBeInstanceOf(Array)
  expect(typeof (encKeys[0])).toEqual('string')
  expect(typeof (encKeys[1])).toEqual('string')
  expect(encKeys[0]).toMatch(/-----BEGIN CRYPT4GH PRIVATE KEY-----/)
  expect(encKeys[0]).toMatch(/-----END CRYPT4GH PRIVATE KEY-----/)
  expect(encKeys[1]).toMatch(/-----BEGIN CRYPT4GH PUBLIC KEY-----/)
  expect(encKeys[1]).toMatch(/-----END CRYPT4GH PUBLIC KEY-----/)
})

// test encrypt keyfiles without password
test('encrpt secret key and public key without password', async () => {
  const keys = await index.keyfiles.encryption_keyfiles([seckey, pubkey])
  expect(keys[0]).toBeInstanceOf(Uint8Array)
  expect(keys[1]).toBeInstanceOf(Uint8Array)
  expect(keys[0].length).toEqual(new Uint8Array(32).length)
  expect(keys[1].length).toEqual(new Uint8Array(32).length)
})

// test encrypt keyfiles with password
test('encrpt secret key and public key with password', async () => {
  const keys = await index.keyfiles.encryption_keyfiles([seckeyPass, pubkeyPass], 'gunpass')
  expect(keys[0]).toBeInstanceOf(Uint8Array)
  expect(keys[1]).toBeInstanceOf(Uint8Array)
  expect(keys[0].length).toEqual(new Uint8Array(32).length)
  expect(keys[1].length).toEqual(new Uint8Array(32).length)
})
