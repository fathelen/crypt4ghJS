/* eslint no-undef: */
// const index = require('crypt4gh_js')
import * as crypt4GHJS from 'crypt4gh_js'
import * as fs from 'fs'

// const fs = require('fs')

const ts = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAgrpd+v2ZGymbextTp5nMt298h1yEFBigB+bS+1WJT/lM=\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nfQCgFp/dPaDOELnzrgEEQUeOmOlMj9M/dTP7bIiuxyw=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const ts2 = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAErnfoX48n1p21KYPJF39qwARY2hhY2hhMjBfcG9seTEzMDUAPB2VckJsR/5iz35Zg5VO2VRkdIStoFIL0681lrdKlpn80dA7bH+vRcQc1+LVT4vptEt7EC5eXltE07uNhA==\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp2 = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nKK2of4G9P49mpUE1PVDia+hTSQ8VWJNXxkSG4m6OiUc=\n-----END CRYPT4GH PUBLIC KEY-----\n'

const seckey = new Uint8Array([82, 33, 99, 16, 74, 205, 109, 244, 142, 130,  35, 140, 171, 177, 28,  66, 204, 127,  32, 168, 101, 240, 31, 13, 216, 205, 126, 242, 34, 101, 100, 42 ])
const pubkey = new Uint8Array([9, 107, 0, 216, 185, 51, 243, 3, 106, 226, 219, 28, 39, 87, 124, 207, 225, 146, 6, 3, 149, 85, 8, 144, 173, 125, 56, 107, 183, 181, 90, 0 ])
// überholte tests

// generate keys

// Test Case 1: generate keypair without password
test('generate keypair without password', async () => {
  const keys = await crypt4GHJS.keygen.keygen()
  expect(keys).toBeInstanceOf(Array)
  expect(keys[0]).toMatch(/^-----BEGIN CRYPT4GH PRIVATE KEY-----(\n)(.{72})(\n)-----END CRYPT4GH PRIVATE KEY-----(\n)$/)
  expect(keys[1]).toMatch(/^-----BEGIN CRYPT4GH PUBLIC KEY-----(\n)(.{44})(\n)-----END CRYPT4GH PUBLIC KEY-----(\n)$/)
  // fs.appendFileSync('Data4Tests/testcase1_secret', keys[0])
  // fs.appendFileSync('Data4Tests/testcase1_public', keys[1])
})

// Test Case 2: generate keypair with password
test('generate keypair with password', async () => {
  const keys = await crypt4GHJS.keygen.keygen('abc')
  expect(keys).toBeInstanceOf(Array)
  expect(keys[0]).toMatch(/^-----BEGIN CRYPT4GH PRIVATE KEY-----(\n)(.{160})(\n)-----END CRYPT4GH PRIVATE KEY-----(\n)$/)
  expect(keys[1]).toMatch(/^-----BEGIN CRYPT4GH PUBLIC KEY-----(\n)(.{44})(\n)-----END CRYPT4GH PUBLIC KEY-----(\n)$/)
  // fs.appendFileSync('Data4Tests/testcase2_secret', keys[0])
  // fs.appendFileSync('Data4Tests/testcase2_public', keys[1])
})
// Test Case 3: generate key with password, illegal character (error)
test('generate key with password, illegal character (error)', async () => {
  const keys = await crypt4GHJS.keygen.keygen('   ')
  expect(keys).toBe(undefined)
})

// check keyfiles

// Test Case 4: check if keyfile can be decrypted without password
test('check if keyfile can be decrypted without password', async () => {
  const seckey = fs.readFileSync('Data4Tests/testcase1_secret').toString()
  const pubkey = fs.readFileSync('Data4Tests/testcase1_public').toString()
  const decryptedKeys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey, pubkey])
  expect(decryptedKeys).toBeInstanceOf(Array)
  expect(decryptedKeys[0]).toBeInstanceOf(Uint8Array) // seckey: Uint8Array(32) [ 82,  33,  99,  16,  74, 205, 109, 244, 142, 130,  35, 140, 171, 177,  28,  66, 204, 127,  32, 168, 101, 240,  31,  13, 216, 205, 126, 242,  34, 101, 100,  42 ]
  expect(decryptedKeys[1]).toBeInstanceOf(Uint8Array) // pubkey: Uint8Array(32) [ 9, 107,   0, 216, 185,  51, 243,   3, 106, 226, 219,  28,  39,  87, 124, 207, 225, 146,   6,   3, 149,  85,   8, 144, 173, 125,  56, 107, 183, 181,  90,   0 ]
  expect(decryptedKeys[0].length).toBe(32)
  expect(decryptedKeys[1].length).toBe(32)
})
// Test Case 5: check if keyfile can be decrypted with password
test('check if keyfile can be decrypted with password', async () => {
  const seckey = fs.readFileSync('Data4Tests/testcase2_secret').toString()
  const pubkey = fs.readFileSync('Data4Tests/testcase2_public').toString()
  const decryptedKeys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey, pubkey], 'abc')
  expect(decryptedKeys).toBeInstanceOf(Array)
  expect(decryptedKeys[0]).toBeInstanceOf(Uint8Array) // seckey: Uint8Array(32) [ 239,  53, 227, 105, 157, 144,  90, 226, 118, 104,  90,  48,  37,  89,  73, 246, 10, 150, 243, 176, 181,  40, 210,  96, 102, 181, 168,  18,  59, 126, 206,  33 ]
  expect(decryptedKeys[1]).toBeInstanceOf(Uint8Array) // pubkey:  Uint8Array(32) [ 185, 166, 222, 208,  72, 148, 218, 76,  96,  57,  73, 228, 246,  63, 197, 247,  81, 153, 179, 159, 209, 169, 105, 116, 255, 125, 223, 244, 119, 168, 113,   9]
  expect(decryptedKeys[0].length).toBe(32)
  expect(decryptedKeys[1].length).toBe(32)
})
// Test Case 6: check error if keyfile is decrypted with wrong password
test('check error if keyfile is decrypted with wrong password', async () => {
  const seckey = fs.readFileSync('Data4Tests/testcase2_secret').toString()
  const pubkey = fs.readFileSync('Data4Tests/testcase2_public').toString()
  const decryptedKeys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey, pubkey], 'def')
  expect(decryptedKeys).toBe(undefined)
})
// Test Case 7: wrong pubkey file
test('wrong pubkey file', async () => {
  const seckey = fs.readFileSync('Data4Tests/testcase1_secret').toString()
  const pubkey = fs.readFileSync('Data4Tests/testcase7_wrongPubkeyFile').toString()
  const decryptedKeys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey, pubkey])
  expect(decryptedKeys).toBe(undefined)
})

// Test Case 8: wrong seckey file
test('wrong pubkey file', async () => {
  const seckey = fs.readFileSync('Data4Tests/testcase8_wrongSeckeyFile').toString()
  const pubkey = fs.readFileSync('Data4Tests/testcase2_public').toString()
  const decryptedKeys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey, pubkey])
  expect(decryptedKeys).toBe(undefined)
})

// encryption
// Test Case 9: encryption without additional parameters, single header packet
test(' encryption without additional parameters, single header packet', async () => {
  const edit = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array) // header: Uint8Array(124) [99, 114, 121, 112, 116,  52, 103, 104,   1,   0,   0,   0, 1,   0,   0,   0, 108,   0,   0,   0,   0,   0,   0,   0, 9, 107,   0, 216, 185,  51, 243,   3, 106, 226, 219,  28, 39,  87, 124, 207, 225, 146,   6,   3, 149,  85,   8, 144, 173, 125,  56, 107, 183, 181,  90,   0, 226, 193,  29, 216, 179,  89,  47, 223, 251, 210, 155, 179,  31, 179, 119, 234, 231, 100, 250,  96, 220, 110, 121, 173, 121,  91,  17,  37, 179,  55, 157, 133, 204, 128, 215,  79,  64,  34, 165, 250, 109,  70, 104, 248,43,  14, 248, 201, 198, 110, 224, 136, 173, 254,  77, 253, 167, 200,  26, 177, 233, 179,  19, 138, 133,  97, 241, 182]
  expect(header[1]).toBeInstanceOf(Uint8Array) // sessionkey: Uint8Array(32) [ 82, 213,  64,  93,  11, 220,  42, 126, 210,  28, 255, 128, 228,  55,  98,  16, 191, 110, 190,  66, 212, 194,  34,  34, 132,  93,  73, 234, 163, 101, 169, 105]
  expect(header[0].length).toBe(124)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase9.c4gh')
  /*
  console.log(header[0])
  console.log(header[0].subarray(98))
  console.log(header[1]) */
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
           // writeStream.end()
          })
  }
})
// Test Case 10: encryption with editlist even, single header packet
// Test Case 11: encryption with editlist odd, single header packet
// Test Case 12: encryption with editlist just 1 number, single header packet
// Test Case 13: encryption with editlist negative number, single header packet (error)
// Test Case 14: encryption with editlist not a number, single header packet (error)
// Test Case 15: encryption special case 1, single header packet
// Test Case 16: encryption special case 2, single header packet
// Test Case 17: encryption special case 3, single header packet
// Test Case 18: encryption special case 4, single header packet
// Test Case 19: encryption with blocks one block, single header packet
// Test Case 20: encryption with blocks multiple block, single header packet
// Test Case 21: encryption with blocks negative block, single header packet
// Test Case 22: encryption with blocks not a number block, single header packet
// Test Case 23: error if encryption and blocks, single header packet
// Test Case 24: encryption without additional parameters, multiple header packets
// Test Case 25: encryption with editlist even, multiple header packets
// Test Case 26: encryption with editlist odd, multiple header packets
// Test Case 27: encryption with editlist just 1 number, multiple header packets
// Test Case 28: encryption with editlist negative number, multiple header packets (error)
// Test Case 29: encryption with editlist not a number, multiple header packets (error)
// Test Case 30: encryption special case 1, multiple header packets
// Test Case 31: encryption special case 2, multiple header packets
// Test Case 32: encryption special case 3, multiple header packets
// Test Case 33: encryption special case 4, multiple header packets
// Test Case 34: encryption with blocks one block, multiple header packets
// Test Case 35: encryption with blocks multiple block, multiple header packets
// Test Case 36: encryption with blocks negative block, multiple header packets
// Test Case 37: encryption with blocks not a number block, multiple header packets
// Test Case 38: error if encryption and blocks, multiple header packets

// check fileformat
// Test Case 39: check fileformat, crypt4GH = true

// Test Case 40: check fileformat, crypt4GH = wrong

// reencryption
// Test Case 40: reencryption, without editlist, one header packet, for one new header packet
// Test Case 41: reencryption, without editlist, one header packet, for multiple new header packets
// Test Case 42: reencryption, without editlist, multiple header packets, for one new header packet
// Test Case 43: reencryption, without editlist, multiple header packets, for multiple new header packets
// Test Case 44: reencryption, with editlist, one header packet, for one new header packet
// Test Case 45: reencryption, with editlist, one header packet, for multiple new header packets
// Test Case 46: reencryption, with editlist, multiple header packets, for one new header packet
// Test Case 47: reencryption, with editlist, multiple header packets, for multiple new header packets

// rearrangement
// Test Case 48: rearrangement, without editlist before, one header packet, for one new header packet
// Test Case 49: rearrangement, without editlist before, one header packet, for multiple new header packets
// Test Case 50: rearrangement, without editlist before, multiple header packets, for one new header packet
// Test Case 51: rearrangement, without editlist before, multiple header packets, for multiple new header packets
// Test Case 52: rearrangement, without editlist before, multiple header packets, for multiple new header packets
// Test Case 53: rearrangement, with editlist before, one header packet, for one new header packet
// Test Case 54: rearrangement, with editlist before, one header packet, for multiple new header packets
// Test Case 55: rearrangement, with editlist before, multiple header packets, for one new header packet
// Test Case 56: rearrangement, with editlist before, multiple header packets, for multiple new header packets
// Test Case 57: rearrangement, with editlist before, multiple header packets, for multiple new header packets
// Test Case 58:rearrangement, with editlist before, new edit out of range (error)

// decryption

// decryption of encryption
// Test Case 59: decryptin: encryption without additional parameters, single header packet
// Test Case 60: decryptin: encryption with editlist even, single header packet
// Test Case 61: decryptin: encryption with editlist odd, single header packet
// Test Case 62: decryptin: encryption with editlist just 1 number, single header packet
// Test Case 63: decryptin: encryption special case 1, single header packet
// Test Case 64: decryptin: encryption special case 2, single header packet
// Test Case 65: decryptin: encryption special case 3, single header packet
// Test Case 66: decryptin: encryption special case 4, single header packet
// Test Case 67: decryptin: encryption with blocks one block, single header packet
// Test Case 68: decryptin: encryption with blocks multiple block, single header packet
// Test Case 69: decryptin: encryption with blocks negative block, single header packet
// Test Case 70: decryptin: encryption with blocks not a number block, single header packet
// Test Case 71: decryptin: encryption without additional parameters, multiple header packets
// Test Case 72: decryptin: encryption with editlist even, multiple header packets
// Test Case 73: decryptin: encryption with editlist odd, multiple header packets
// Test Case 74: decryptin: encryption with editlist just 1 number, multiple header packets
// Test Case 75: decryptin: encryption special case 1, multiple header packets
// Test Case 76: decryptin: encryption special case 2, multiple header packets
// Test Case 77: decryptin: encryption special case 3, multiple header packets
// Test Case 78: decryptin: encryption special case 4, multiple header packets
// Test Case 79: decryptin: encryption with blocks one block, multiple header packets
// Test Case 80: decryptin: encryption with blocks multiple block, multiple header packets

// decryption of reencryption

// Test Case 81: decryption: reencryption, without editlist, one header packet, for one new header packet
// Test Case 82: decryption: reencryption, without editlist, one header packet, for multiple new header packets
// Test Case 83: decryption: reencryption, without editlist, multiple header packets, for one new header packet
// Test Case 84: decryption: reencryption, without editlist, multiple header packets, for multiple new header packets
// Test Case 85: decryption: reencryption, with editlist, one header packet, for one new header packet
// Test Case 86: decryption: reencryption, with editlist, one header packet, for multiple new header packets
// Test Case 87: decryption: reencryption, with editlist, multiple header packets, for one new header packet
// Test Case 88: decryption: reencryption, with editlist, multiple header packets, for multiple new header packets

// decryption of rearrangement
// Test Case 89: decryption: rearrangement, without editlist before, one header packet, for one new header packet
// Test Case 90: decryption: rearrangement, without editlist before, one header packet, for multiple new header packets
// Test Case 91: decryption: rearrangement, without editlist before, multiple header packets, for one new header packet
// Test Case 92: decryption: rearrangement, without editlist before, multiple header packets, for multiple new header packets
// Test Case 93: decryption: rearrangement, without editlist before, multiple header packets, for multiple new header packets
// Test Case 94 decryption: rearrangement, with editlist before, one header packet, for one new header packet
// Test Case 95: decryption: rearrangement, with editlist before, one header packet, for multiple new header packets
// Test Case 96: decryption: rearrangement, with editlist before, multiple header packets, for one new header packet
// Test Case 97: decryption: rearrangement, with editlist before, multiple header packets, for multiple new header packets
// Test Case 98: decryption: rearrangement, with editlist before, multiple header packets, for multiple new header packets

// decryption decryptzing blocks

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
test('encryption, read chunks, no edit, no blocks', async () => {
  edit = null
  block = null
  const header = index.encryption.encHeader(encSeckeyPass, [encPubkeyPass], block, edit)
  // fs.appendFileSync('testData\\readChunks.crypt4gh', header[0])
  expect(header[0]).toBeInstanceOf(Uint8Array)
  if (header[1]) {
    const readStream = fs.createReadStream('testData\\abcd.txt')
    readStream
      .on('data', async function (d) {
        const val = await index.encryption.pureEncryption(d, header[1])
        // fs.appendFileSync('testData\\readChunks.crypt4gh', val)
        await expect(val).toBeInstanceOf(Uint8Array)
      })
  }
})

test('encryption, read chunks, no edit, blocks', async () => {
  edit = null
  block = [1, 2]
  let counter = 0
  const header = index.encryption.encHeader(encSeckeyPass, [encPubkeyPass])
  // fs.appendFileSync('testData\\readChunksBlocks.crypt4gh', header[0])
  expect(header[0]).toBeInstanceOf(Uint8Array)
  if (header[1]) {
    const readStream = fs.createReadStream('testData\\abcd.txt')
    readStream
      .on('data', async function (d) {
        counter++
        if (block.includes(counter) === true) {
          const val = await index.encryption.pureEncryption(d, header[1])
          // fs.appendFileSync('testData\\readChunksBlocks.crypt4gh', val)
          await expect(val).toBeInstanceOf(Uint8Array)
        }
      })
  }
})

test('encryption, read chunks, edit, no blocks', async () => {
  edit = [0, 10]
  const header = await index.encryption.encHeaderEdit(encSeckeyPass, [encPubkeyPass], edit)
  // fs.appendFileSync('testData\\readChunksEdit.crypt4gh', header[0][0])
  expect(header[0][0]).toBeInstanceOf(Uint8Array)
  if (header) {
    const readStream = fs.createReadStream('testData\\abcd.txt')
    readStream
      .on('data', async function (d) {
        const val = await index.encryption.pureEncryption(d, header[1])
        // fs.appendFileSync('testData\\readChunksEdit.crypt4gh', val)
        await expect(val).toBeInstanceOf(Uint8Array)
      })
  }
})

// decryption without password, encblocks or decblocks, with odd editlist (3)
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testDec), encSeckeyPass, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // st textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

test('decryption, read chunks, no edit, no blocks', async () => {
  const readStream = fs.createReadStream('testData\\readChunks.crypt4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const val = await index.decryption.header_deconstruction(Uint8Array.from(d), encSeckeyPass)
      await expect(val).toBeInstanceOf(Array)
      const readStream2 = fs.createReadStream('testData\\readChunks.crypt4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          const plaintext = await index.decryption.pureDecryption(Uint8Array.from(d2), val[0])
          // fs.appendFileSync('testData\\chunkDec.txt', plaintext)
          expect(plaintext).toBeInstanceOf(Uint8Array)
        })
      readStream.destroy()
    })
})

test('decryption, read chunks, no edit, blocks', async () => {
  const readStream = fs.createReadStream('testData\\readChunksBlocks.crypt4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const val = await index.decryption.header_deconstruction(Uint8Array.from(d), encSeckeyPass)
      await expect(val).toBeInstanceOf(Array)
      const readStream2 = fs.createReadStream('testData\\readChunksBlocks.crypt4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          const plaintext = await index.decryption.pureDecryption(Uint8Array.from(d2), val[0])
          // fs.appendFileSync('testData\\chunkDecBlocks.txt', plaintext)
          expect(plaintext).toBeInstanceOf(Uint8Array)
        })
      readStream.destroy()
    })
})

test('decryption, read chunks, edit, no blocks', async () => {
  let counter = 0
  const readStream = fs.createReadStream('testData\\readChunksEdit.crypt4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const val = await index.decryption.header_deconstruction(Uint8Array.from(d), encSeckeyPass)
      const edits = index.decryption.pureEdit(val)
      await expect(val).toBeInstanceOf(Array)
      const readStream2 = fs.createReadStream('testData\\readChunksEdit.crypt4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          if (Array.from(edits[0].keys()).includes(counter)) {
            const plaintext = await index.decryption.pureDecryption(Uint8Array.from(d2), val[0])
            const aplliedEdit = index.decryption.applyEditlist(edits[0].get(counter), plaintext)
            // fs.appendFileSync('testData\\chunkDecEdits.txt', aplliedEdit)
            expect(aplliedEdit).toBeInstanceOf(Uint8Array)
          }
        })
      readStream.destroy()
    })
})

test('decryption, read chunks, no edit, blocks, but only wants to decrypt x blocks', async () => {
  const wantedBlocks = [2]
  let counter = 0
  const readStream = fs.createReadStream('testData\\readChunksBlocks.crypt4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const val = await index.decryption.header_deconstruction(Uint8Array.from(d), encSeckeyPass)
      await expect(val).toBeInstanceOf(Array)
      const readStream2 = fs.createReadStream('testData\\readChunksBlocks.crypt4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          if (wantedBlocks.includes(counter)) {
            const plaintext = await index.decryption.pureDecryption(Uint8Array.from(d2), val[0])
            // fs.appendFileSync('testData\\chunkDecWantedBlocks.txt', plaintext)
            expect(plaintext).toBeInstanceOf(Uint8Array)
          }
        })
      readStream.destroy()
    })
})

test('reeencryption', async () => {
  const readStream = fs.createReadStream('testData\\readChunks.crypt4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = index.reeencryption.streamReencryptHeader(Uint8Array.from(d), [encPubkey, encPubkeyPass], encSeckeyPass)
      await expect(reencryptHeader).toBeInstanceOf(Array)
      // fs.appendFileSync('testData\\chunkReencryption.crypt4gh', reencryptHeader[0])
      const readStream2 = fs.createReadStream('testData\\readChunks.crypt4gh', { start: reencryptHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('testData\\chunkReencryption.crypt4gh', d2)
        })
      readStream.destroy()
    })
})

test('decryption of reencryption', async () => {
  const readStream = fs.createReadStream('testData\\chunkReencryption.crypt4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const val = await index.decryption.header_deconstruction(Uint8Array.from(d), encSeckeyPass)
      await expect(val).toBeInstanceOf(Array)
      const readStream2 = fs.createReadStream('testData\\chunkReencryption.crypt4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          const plaintext = await index.decryption.pureDecryption(Uint8Array.from(d2), val[0])
          // fs.appendFileSync('testData\\chunkDecReencryption.txt', plaintext)
          expect(plaintext).toBeInstanceOf(Uint8Array)
        })
      readStream.destroy()
    })
})

test('rearrangement', async () => {
  const editlist = [0, 5]
  const readStream = fs.createReadStream('testData\\readChunks.crypt4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await index.rearrangment.streamRearrange(Uint8Array.from(d), encSeckeyPass, [encPubkey, encPubkeyPass], editlist)
      await expect(rearrangeHeader[0]).toBeInstanceOf(Uint8Array)
      // fs.appendFileSync('testData\\chunkRearrangement.crypt4gh', rearrangeHeader[0])
      const readStream2 = fs.createReadStream('testData\\readChunks.crypt4gh', { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('testData\\chunkRearrangement.crypt4gh', d2)
        })
      readStream.destroy()
    })
})

test('decryption, rearrangement', async () => {
  let counter = 0
  const readStream = fs.createReadStream('testData\\chunkRearrangement.crypt4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const val = await index.decryption.header_deconstruction(Uint8Array.from(d), encSeckey)
      const edits = index.decryption.pureEdit(val)
      await expect(val).toBeInstanceOf(Array)
      const readStream2 = fs.createReadStream('testData\\chunkRearrangement.crypt4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          if (Array.from(edits[0].keys()).includes(counter)) {
            const plaintext = await index.decryption.pureDecryption(Uint8Array.from(d2), val[0])
            const aplliedEdit = index.decryption.applyEditlist(edits[0].get(counter), plaintext)
            fs.appendFileSync('testData\\chunkDecRearrangement.txt', aplliedEdit)
            expect(aplliedEdit).toBeInstanceOf(Uint8Array)
          }
        })
      readStream.destroy()
    })
})

test('rearrangement with edit before', async () => {
  const editlist = [0, 10]
  const readStream = fs.createReadStream('testData\\readChunksEdit.crypt4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await index.rearrangment.streamRearrange(Uint8Array.from(d), encSeckeyPass, [encPubkey, encPubkeyPass], editlist)
      await expect(rearrangeHeader[0]).toBeInstanceOf(Uint8Array)
      // fs.appendFileSync('testData\\chunkRearrangementEdit.crypt4gh', rearrangeHeader[0])
      const readStream2 = fs.createReadStream('testData\\readChunksEdit.crypt4gh', { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('testData\\chunkRearrangementEdit.crypt4gh', d2)
        })
      readStream.destroy()
    })
})

test('decryption, rearrangement', async () => {
  let counter = 0
  const readStream = fs.createReadStream('testData\\chunkRearrangementEdit.crypt4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const val = await index.decryption.header_deconstruction(Uint8Array.from(d), encSeckey)
      const edits = index.decryption.pureEdit(val)
      await expect(val).toBeInstanceOf(Array)
      const readStream2 = fs.createReadStream('testData\\chunkRearrangementEdit.crypt4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          if (Array.from(edits[0].keys()).includes(counter)) {
            const plaintext = await index.decryption.pureDecryption(Uint8Array.from(d2), val[0])
            const aplliedEdit = index.decryption.applyEditlist(edits[0].get(counter), plaintext)
            // fs.appendFileSync('testData\\chunkDecRearrangementEdit.txt', aplliedEdit)
            expect(aplliedEdit).toBeInstanceOf(Uint8Array)
          }
        })
      readStream.destroy()
    })
})

// test kompatibilität python
test('decryption pythonfile', async () => {
  const readStream = fs.createReadStream('testData\\kompatibel.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const val = await index.decryption.header_deconstruction(Uint8Array.from(d), pythonKeySec)
      const readStream2 = fs.createReadStream('testData\\kompatibel.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          const plaintext = await index.decryption.pureDecryption(Uint8Array.from(d2), val[0])
          // fs.appendFileSync('testData\\pythonkompatibel.txt', plaintext)
          expect(plaintext).toBeInstanceOf(Uint8Array)
        })
      readStream.destroy()
    })
})

// test kompatibilität python
test('decryption pythonfile', async () => {
  const readStream = fs.createReadStream('testData\\kompatibelRange.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const val = await index.decryption.header_deconstruction(Uint8Array.from(d), pythonKeySec)
      const readStream2 = fs.createReadStream('testData\\kompatibelRange.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          const plaintext = await index.decryption.pureDecryption(Uint8Array.from(d2), val[0])
          fs.appendFileSync('testData\\pythonkompatibelRange.txt', plaintext)
          expect(plaintext).toBeInstanceOf(Uint8Array)
        })
      readStream.destroy()
    })
})

// find python keys
test('decrpt secret key and public key with password', async () => {
  const keys = await index.keyfiles.encryption_keyfiles([pythonSec, pythonPub], 'gunpass')
  expect(keys[0]).toBeInstanceOf(Uint8Array)
})

test('encryption, read chunks, no edit, no blocks for python', async () => {
  edit = null
  block = null
  const header = index.encryption.encHeader(pythonKeySec, [pythonKeyPub], block, edit)
  // fs.appendFileSync('testData\\pythonTest.crypt4gh', header[0])
  expect(header[0]).toBeInstanceOf(Uint8Array)
  if (header[1]) {
    const readStream = fs.createReadStream('testData\\abcd.txt')
    readStream
      .on('data', async function (d) {
        const val = await index.encryption.pureEncryption(d, header[1])
        // fs.appendFileSync('testData\\pythonTest.crypt4gh', val)
        await expect(val).toBeInstanceOf(Uint8Array)
      })
  }
})

test('python compitbility Edit', async () => {
  edit = [10000, 10, 2000, 5]
  const header = await index.encryption.encHeaderEdit(pythonKeySec, [pythonKeyPub], edit)
  // fs.appendFileSync('testData\\pythonTestEdit.crypt4gh', header[0][0])
  expect(header[0][0]).toBeInstanceOf(Uint8Array)
  if (header) {
    const readStream = fs.createReadStream('testData\\abcd.txt')
    readStream
      .on('data', async function (d) {
        const val = await index.encryption.pureEncryption(d, header[1])
        // fs.appendFileSync('testData\\pythonTestEdit.crypt4gh', val)
        await expect(val).toBeInstanceOf(Uint8Array)
      })
  }
}) */
