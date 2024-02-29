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

const seckeyPass = new Uint8Array([ 239,  53, 227, 105, 157, 144,  90, 226, 118, 104,  90,  48,  37,  89,  73, 246, 10, 150, 243, 176, 181,  40, 210,  96, 102, 181, 168,  18,  59, 126, 206,  33 ])
const pubkeyPass = new Uint8Array([ 185, 166, 222, 208,  72, 148, 218, 76,  96,  57,  73, 228, 246,  63, 197, 247,  81, 153, 179, 159, 209, 169, 105, 116, 255, 125, 223, 244, 119, 168, 113,   9])

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
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array) 
  expect(header[1]).toBeInstanceOf(Uint8Array)
  expect(header[0].length).toBe(124)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase9.c4gh')
  // writeStream.write(header[0])
  if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
          //  writeStream.end()
          })
  }
})
// Test Case 10: encryption with editlist even, single header packet
test('encryption with editlist even, single header packet', async () => {
  const edit = [0, 10, 70000,5]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array)
  expect(header[1]).toBeInstanceOf(Uint8Array)
  expect(header[0].length).toBe(232)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase10.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
           // writeStream.end()
          })
  }
})
// Test Case 11: encryption with editlist odd, single header packet
test('encryption with editlist odd, single header packet', async () => {
  const edit = [0, 5, 2621390]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array)
  expect(header[0].length).toBe(224)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase11.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
           // writeStream.end()
          })
  }
})
// Test Case 12: encryption with editlist just 1 number, single header packet
test('encryption with editlist just 1 number, single header packet', async () => {
  const edit = [2621390]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array)
  expect(header[1]).toBeInstanceOf(Uint8Array)
  expect(header[0].length).toBe(208)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase12.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
            // writeStream.end()
          })
  }
})
// Test Case 13: encryption with editlist negative number, single header packet (error)
test('encryption with editlist negative number, single header packet (error)', async () => {
  const edit = [-10]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBe(undefined)
   if (header) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            }
          })
          .on('end', (d) => {
          }) 
  }
})
// Test Case 14: encryption with editlist not a number, single header packet (error)
test('encryption with editlist not a number, single header packet (error)', async () => {
  const edit = ['a']
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBe(undefined)
   if (header) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            }
          })
          .on('end', (d) => {
          }) 
  }
})
// Test Case 15: encryption special case 1, single header packet
// Test Case 16: encryption special case 2, single header packet
// Test Case 17: encryption special case 3, single header packet
// Test Case 18: encryption special case 4, single header packet
// Test Case 19: encryption with blocks one block, single header packet
test('encryption with blocks one block, single header packet', async () => {
  const edit = null
  const blocks = [1]
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array)
  expect(header[1]).toBeInstanceOf(Uint8Array)
  expect(header[0].length).toBe(124)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase19.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          if (text) {
            expect(text).toBeInstanceOf(Uint8Array)
            expect(text.length).toBe(65564)
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
           // writeStream.end()
          })
  }
})
// Test Case 20: encryption with blocks multiple block, single header packet
test('encryption with blocks multiple block, single header packet', async () => {
  const edit = null
  const blocks = [1,4]
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array)
  expect(header[1]).toBeInstanceOf(Uint8Array)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase20.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          if (text) {
            expect(text).toBeInstanceOf(Uint8Array)
            expect(text.length).toBe(65564)
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
            // writeStream.end()
          })
  }
})
// Test Case 21: encryption with blocks negative block, single header packet (error)
test('encryption with blocks negative block, single header packet (error)', async () => {
  const edit = null
  const blocks = [-1]
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBe(undefined)
})
// Test Case 22: encryption with blocks not a number block, single header packet
test('encryption with blocks not a number block, single header packet', async () => {
  const edit = null
  const blocks = ['a']
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBe(undefined)
})
// Test Case 23: error if encryption and blocks, single header packet
test('error if encryption and blocks, single header packet', async () => {
  const edit = [1,2]
  const blocks = [1]
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey], edit, blocks)
  expect(header).toBe(undefined)
})
// Test Case 24: encryption without additional parameters, multiple header packets
test('encryption without additional parameters, multiple header packets', async () => {
  const edit = null
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase24.c4gh')
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array)
  expect(header[1]).toBeInstanceOf(Uint8Array)
  expect(header[0].length).toBe(232)
  expect(header[1].length).toBe(32)
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
           // writeStream.end()
          }) 
  }
})
// Test Case 25: encryption with editlist even, multiple header packets
test('encryption with editlist even, multiple header packets', async () => {
  const edit = [0, 10, 70000,5]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array) 
  expect(header[1]).toBeInstanceOf(Uint8Array) 
  expect(header[0].length).toBe(448)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase25.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
           // writeStream.end()
          })
  }
})
// Test Case 26: encryption with editlist odd, multiple header packets
test('encryption with editlist odd, single header packet', async () => {
  const edit = [0, 5, 2621390]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array)
  expect(header[1]).toBeInstanceOf(Uint8Array)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase26.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
           // writeStream.end()
          })
  }
})
// Test Case 27: encryption with editlist just 1 number, multiple header packets
test('encryption with editlist just 1 number, single header packet', async () => {
  const edit = [2621390]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array)
  expect(header[1]).toBeInstanceOf(Uint8Array)
  expect(header[0].length).toBe(400)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase27.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
           // writeStream.end()
          })
  }
})
// Test Case 28: encryption with editlist negative number, multiple header packets (error)
test('encryption with editlist negative number, multiple header packets (error)', async () => {
  const edit = [-10]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBe(undefined)
   if (header) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            }
          })
          .on('end', (d) => {
          }) 
  }
})
// Test Case 29: encryption with editlist not a number, multiple header packets (error)
test('encryption with editlist not a number, multiple header packets (error)', async () => {
  const edit = ['a']
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBe(undefined)
   if (header) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            }
          })
          .on('end', (d) => {
          }) 
  }
})
// Test Case 30: encryption special case 1, multiple header packets
// Test Case 31: encryption special case 2, multiple header packets
// Test Case 32: encryption special case 3, multiple header packets
// Test Case 33: encryption special case 4, multiple header packets

// Test Case 34: encryption with blocks one block, multiple header packets
test('encryption with blocks one block, multiple header packets', async () => {
  const edit = null
  const blocks = [1]
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array)
  expect(header[1]).toBeInstanceOf(Uint8Array)
  expect(header[0].length).toBe(232)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase34.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          if (text) {
            expect(text).toBeInstanceOf(Uint8Array)
            expect(text.length).toBe(65564)
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
          // writeStream.end()
          })
  }
})
// Test Case 35: encryption with blocks multiple block, multiple header packets
test('encryption with blocks multiple block, multiple header packets', async () => {
  const edit = null
  const blocks = [1,4]
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array)
  expect(header[1]).toBeInstanceOf(Uint8Array)
  expect(header[0].length).toBe(232)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase35.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          if (text) {
            expect(text).toBeInstanceOf(Uint8Array)
            expect(text.length).toBe(65564)
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
           // writeStream.end()
          })
  }
})
// Test Case 36: encryption with blocks negative block, multiple header packets
test('encryption with blocks negative block, multiple header packets(error)', async () => {
  const edit = null
  const blocks = [-1]
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBe(undefined)
})
// Test Case 37: encryption with blocks not a number block, multiple header packets
test(' encryption with blocks not a number block, multiple header packets(error))', async () => {
  const edit = null
  const blocks = ['a']
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBe(undefined)
})
// Test Case 38: error if encryption and blocks, multiple header packets
test('error if encryption and blocks, multiple header packets', async () => {
  const edit = [1,2]
  const blocks = [1]
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBe(undefined)
})
// Test Case 39: encryption with multiple editlist, just even,  multiple header packets
test('encryption with multiple editlist, just even,  multiple header packets', async () => {
  const edit = [[0, 10, 70000,5], [0,5]]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array) 
  expect(header[1]).toBeInstanceOf(Uint8Array) 
  expect(header[0].length).toBe(432)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase39.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
           // writeStream.end()
          })
  }
})
// Test Case 40: encryption with multiple editlist, just odd, multiple header packets
test('encryption with multiple editlist, just odd, multiple header packets', async () => {
  const edit = [[0, 5, 2621390], [0, 15, 2621380]]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array) 
  expect(header[1]).toBeInstanceOf(Uint8Array) 
  expect(header[0].length).toBe(432)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase40.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
            // writeStream.end()
          })
  }
})
// Test Case 41: encryption with multiple editlist, odd and even, multiple header packets
test('encryption with multiple editlist, odd and even, multiple header packets', async () => {
  const edit = [[0, 5, 2621390], [0, 15, 2621370,10]]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBeInstanceOf(Array)
  expect(header[0]).toBeInstanceOf(Uint8Array) 
  expect(header[1]).toBeInstanceOf(Uint8Array) 
  expect(header[0].length).toBe(440)
  expect(header[1].length).toBe(32)
  // const writeStream = fs.createWriteStream('Data4Tests/testcase41.c4gh')
  // writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream('Data4Tests/abcd.txt')
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          expect(text).toBeInstanceOf(Uint8Array)
          expect([65564, 65524]).toContain(text.length)
          if (text) {
            // writeStream.write(text)
            }
          })
          .on('end', (d) => {
            // writeStream.end()
          })
  }
})
// Test Case 42: encryption with multiple editlist, including negativ numbers, multiple header packets
test('encryption with multiple editlist, including negativ numbers, multiple header packets', async () => {
  const edit = [[0, 5, -1], [0, 15, 2621370,10]]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBe(undefined)
})
// Test Case 43: encryption with multiple editlist, including nan, multiple header packets
test('encryption with multiple editlist, including nan, multiple header packets', async () => {
  const edit = [[0, 5, 9], [0, 15, 2621370, 'a']]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBe(undefined)
})
// Test Case 44: encryption with multiple editlist, less editlists than header packets, multiple header packets
test('encryption with multiple editlist, less editlists than header packets, multiple header packets', async () => {
  const edit = [[0, 5, 9]]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBe(undefined)
})
// Test Case 45: encryption with multiple editlist, more editlists than header packets, multiple header packets
test('encryption with multiple editlist, more editlists than header packets, multiple header packets', async () => {
  const edit = [[0, 5, 9],[0, 5, 9],[0, 5, 9]]
  const blocks = null
  const header = await crypt4GHJS.encryption.encHead(seckey, [pubkey, pubkeyPass], edit, blocks)
  expect(header).toBe(undefined)
})

// check fileformat

// Test Case 46: check fileformat, crypt4GH = true
test('check fileformat, crypt4GH = true', async () => {
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase11.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let isCrypt4GH = await crypt4GHJS.checkFileformat.check(Uint8Array.from(d), seckey)
      expect(isCrypt4GH).toBe(true)
      readStream.destroy()
    })
}) 

// Test Case 47: check fileformat, crypt4GH = false
test('check fileformat, crypt4GH = false', async () => {
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/abcd.txt', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let isCrypt4GH = await crypt4GHJS.checkFileformat.check(Uint8Array.from(d), seckey)
      expect(isCrypt4GH).toBe(false)
      readStream.destroy()
    })
}) 

// reencryption

// Test Case 48: reencryption, without editlist, one header packet, for one new header packet
test('reencryption, without editlist, one header packet, for one new header packet', async () => {
  const readStream = fs.createReadStream('Data4Tests/testcase9.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = await crypt4GHJS.reeencryption.streamReencryptHeader(Uint8Array.from(d), [pubkeyPass], seckey)
      await expect(reencryptHeader).toBeInstanceOf(Array)
      await expect(reencryptHeader[0]).toBeInstanceOf(Uint8Array)
      await expect(reencryptHeader[0].length).toBe(448)
      await expect(reencryptHeader[1]).toBe(124)
      // fs.appendFileSync('Data4Tests/testcase48.c4gh', reencryptHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase9.c4gh', { start: reencryptHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          await expect([65564, 65524]).toContain(d2.length)
          // fs.appendFileSync('Data4Tests/testcase48.c4gh', d2)
        })
      readStream.destroy()
    })
})


// Test Case 49: reencryption, without editlist, one header packet, for multiple new header packets
test('reencryption, without editlist, one header packet, for multiple new header packets', async () => {
  const readStream = fs.createReadStream('Data4Tests/testcase9.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = await crypt4GHJS.reeencryption.streamReencryptHeader(Uint8Array.from(d), [pubkeyPass, pubkey], seckey)
      await expect(reencryptHeader).toBeInstanceOf(Array)
      await expect(reencryptHeader[0]).toBeInstanceOf(Uint8Array)
      await expect(reencryptHeader[0].length).toBe(664)
      await expect(reencryptHeader[1]).toBe(124)
      // fs.appendFileSync('Data4Tests/testcase49.c4gh', reencryptHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase9.c4gh', { start: reencryptHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          await expect([65564, 65524]).toContain(d2.length)
          // fs.appendFileSync('Data4Tests/testcase49.c4gh', d2)
        })
      readStream.destroy()
    })
})
// Test Case 50: reencryption, without editlist, multiple header packets, for one new header packet
test('reencryption, without editlist, multiple header packets, for one new header packet', async () => {
  const readStream = fs.createReadStream('Data4Tests/testcase24.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = await crypt4GHJS.reeencryption.streamReencryptHeader(Uint8Array.from(d), [pubkey], seckeyPass)
      await expect(reencryptHeader).toBeInstanceOf(Array)
      await expect(reencryptHeader[0]).toBeInstanceOf(Uint8Array)
      await expect(reencryptHeader[0].length).toBe(448)
      await expect(reencryptHeader[1]).toBe(232)
      // fs.appendFileSync('Data4Tests/testcase50.c4gh', reencryptHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase24.c4gh', { start: reencryptHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          await expect([65564, 65524]).toContain(d2.length)
          // fs.appendFileSync('Data4Tests/testcase50.c4gh', d2)
        })
      readStream.destroy()
    })
})
// Test Case 51: reencryption, without editlist, multiple header packets, for multiple new header packets
test('reencryption, without editlist, multiple header packets, for multiple new header packets', async () => {
  const readStream = fs.createReadStream('Data4Tests/testcase24.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = await crypt4GHJS.reeencryption.streamReencryptHeader(Uint8Array.from(d), [pubkey, pubkeyPass], seckeyPass)
      await expect(reencryptHeader).toBeInstanceOf(Array)
      await expect(reencryptHeader[0]).toBeInstanceOf(Uint8Array)
      await expect(reencryptHeader[0].length).toBe(664)
      await expect(reencryptHeader[1]).toBe(232)
      // fs.appendFileSync('Data4Tests/testcase51.c4gh', reencryptHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase24.c4gh', { start: reencryptHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          await expect([65564, 65524]).toContain(d2.length)
          // fs.appendFileSync('Data4Tests/testcase51.c4gh', d2)
        })
      readStream.destroy()
    })
})
// Test Case 52: reencryption, with editlist, one header packet, for one new header packet
test('reencryption, with editlist, one header packet, for one new header packet', async () => {
  const readStream = fs.createReadStream('Data4Tests/testcase10.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = await crypt4GHJS.reeencryption.streamReencryptHeader(Uint8Array.from(d), [pubkeyPass], seckey)
      await expect(reencryptHeader).toBeInstanceOf(Array)
      await expect(reencryptHeader[0]).toBeInstanceOf(Uint8Array)
      await expect(reencryptHeader[0].length).toBe(448)
      await expect(reencryptHeader[1]).toBe(232)
      // fs.appendFileSync('Data4Tests/testcase52.c4gh', reencryptHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase10.c4gh', { start: reencryptHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          await expect([65564, 65524]).toContain(d2.length)
          // fs.appendFileSync('Data4Tests/testcase52.c4gh', d2)
        })
      readStream.destroy()
    })
})
// Test Case 53: reencryption, with editlist, one header packet, for multiple new header packets
test('reencryption, with editlist, one header packet, for multiple new header packets', async () => {
  const readStream = fs.createReadStream('Data4Tests/testcase10.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = await crypt4GHJS.reeencryption.streamReencryptHeader(Uint8Array.from(d), [pubkeyPass, pubkey], seckey)
      await expect(reencryptHeader).toBeInstanceOf(Array)
      await expect(reencryptHeader[0]).toBeInstanceOf(Uint8Array)
      await expect(reencryptHeader[0].length).toBe(664)
      await expect(reencryptHeader[1]).toBe(232)
      // fs.appendFileSync('Data4Tests/testcase53.c4gh', reencryptHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase10.c4gh', { start: reencryptHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          await expect([65564, 65524]).toContain(d2.length)
          // fs.appendFileSync('Data4Tests/testcase53.c4gh', d2)
        })
      readStream.destroy()
    })
})
// Test Case 54: reencryption, with editlist, multiple header packets, for one new header packet
test('reencryption, with editlist, multiple header packets, for one new header packet', async () => {
  const readStream = fs.createReadStream('Data4Tests/testcase25.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = await crypt4GHJS.reeencryption.streamReencryptHeader(Uint8Array.from(d), [pubkey], seckeyPass)
      await expect(reencryptHeader).toBeInstanceOf(Array)
      await expect(reencryptHeader[0]).toBeInstanceOf(Uint8Array)
      await expect(reencryptHeader[0].length).toBe(448)
      await expect(reencryptHeader[1]).toBe(448)
      // fs.appendFileSync('Data4Tests/testcase54.c4gh', reencryptHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase25.c4gh', { start: reencryptHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          await expect([65564, 65524]).toContain(d2.length)
          // fs.appendFileSync('Data4Tests/testcase54.c4gh', d2)
        })
      readStream.destroy()
    })
})
// Test Case 55: reencryption, with editlist, multiple header packets, for multiple new header packets
test('reencryption, with editlist, multiple header packets, for one new header packet', async () => {
  const readStream = fs.createReadStream('Data4Tests/testcase25.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = await crypt4GHJS.reeencryption.streamReencryptHeader(Uint8Array.from(d), [pubkey, pubkeyPass], seckeyPass)
      await expect(reencryptHeader).toBeInstanceOf(Array)
      await expect(reencryptHeader[0]).toBeInstanceOf(Uint8Array)
      await expect(reencryptHeader[0].length).toBe(664)
      await expect(reencryptHeader[1]).toBe(448)
      // fs.appendFileSync('Data4Tests/testcase55.c4gh', reencryptHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase25.c4gh', { start: reencryptHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          await expect([65564, 65524]).toContain(d2.length)
          // fs.appendFileSync('Data4Tests/testcase55.c4gh', d2)
        })
      readStream.destroy()
    })
})

// rearrangement
// Test Case 56: rearrangement, without editlist before, one header packet, for one new header packet
test('rearrangement, without editlist before, one header packet, for one new header packet', async () => {
  const editlist = [0, 5]
  const readStream = fs.createReadStream('Data4Tests/testcase9.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await crypt4GHJS.rearrangment.streamRearrange(Uint8Array.from(d), seckey, [pubkeyPass], editlist)
      await expect(rearrangeHeader[0]).toBeInstanceOf(Uint8Array)
      // fs.appendFileSync('Data4Tests/testcase56.c4gh', rearrangeHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase9.c4gh', { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('Data4Tests/testcase56.c4gh', d2)
          await expect([65564, 65524]).toContain(d2.length)
        })
      readStream.destroy()
    })
})
// Test Case 57: rearrangement, without editlist before, one header packet, for multiple new header packets
test('rearrangement, without editlist before, one header packet, for multiple new header packets', async () => {
  const editlist = [0, 5]
  const readStream = fs.createReadStream('Data4Tests/testcase9.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await crypt4GHJS.rearrangment.streamRearrange(Uint8Array.from(d), seckey, [pubkeyPass, pubkey], editlist)
      await expect(rearrangeHeader[0]).toBeInstanceOf(Uint8Array)
      // fs.appendFileSync('Data4Tests/testcase57.c4gh', rearrangeHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase9.c4gh', { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('Data4Tests/testcase57.c4gh', d2)
          await expect([65564, 65524]).toContain(d2.length)
        })
      readStream.destroy()
    })
})
// Test Case 58: rearrangement, without editlist before, multiple header packets, for one new header packet
test('rearrangement, without editlist before, one header packet, for multiple new header packets', async () => {
  const editlist = [0, 5]
  const readStream = fs.createReadStream('Data4Tests/testcase24.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await crypt4GHJS.rearrangment.streamRearrange(Uint8Array.from(d), seckey, [pubkey], editlist)
      await expect(rearrangeHeader[0]).toBeInstanceOf(Uint8Array)
      // fs.appendFileSync('Data4Tests/testcase58.c4gh', rearrangeHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase24.c4gh', { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('Data4Tests/testcase58.c4gh', d2)
          await expect([65564, 65524]).toContain(d2.length)
        })
      readStream.destroy()
    })
})
// Test Case 59: rearrangement, without editlist before, multiple header packets, for multiple new header packets
test('rearrangement, without editlist before, one header packet, for multiple new header packets', async () => {
  const editlist = [0, 5]
  const readStream = fs.createReadStream('Data4Tests/testcase24.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await crypt4GHJS.rearrangment.streamRearrange(Uint8Array.from(d), seckey, [pubkey, pubkeyPass], editlist)
      await expect(rearrangeHeader[0]).toBeInstanceOf(Uint8Array)
      // fs.appendFileSync('Data4Tests/testcase59.c4gh', rearrangeHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase24.c4gh', { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('Data4Tests/testcase59.c4gh', d2)
          await expect([65564, 65524]).toContain(d2.length)
        })
      readStream.destroy()
    })
})
// Test Case 60: rearrangement, with editlist before, one header packet, for one new header packet
test('rearrangement, with editlist before, one header packet, for one new header packet', async () => {
  const editlist = [0, 5]
  const readStream = fs.createReadStream('Data4Tests/testcase10.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await crypt4GHJS.rearrangment.streamRearrange(Uint8Array.from(d), seckey, [pubkeyPass], editlist)
      await expect(rearrangeHeader[0]).toBeInstanceOf(Uint8Array)
      // fs.appendFileSync('Data4Tests/testcase60.c4gh', rearrangeHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase10.c4gh', { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('Data4Tests/testcase60.c4gh', d2)
          await expect([65564, 65524]).toContain(d2.length)
        })
      readStream.destroy()
    })
})
// Test Case 61: rearrangement, with editlist before, one header packet, for multiple new header packets
test('rearrangement, with editlist before, one header packet, for multiple new header packets', async () => {
  const editlist = [0, 5]
  const readStream = fs.createReadStream('Data4Tests/testcase10.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await crypt4GHJS.rearrangment.streamRearrange(Uint8Array.from(d), seckey, [pubkeyPass, pubkey], editlist)
      await expect(rearrangeHeader[0]).toBeInstanceOf(Uint8Array)
      // fs.appendFileSync('Data4Tests/testcase61.c4gh', rearrangeHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase10.c4gh', { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('Data4Tests/testcase61.c4gh', d2)
          await expect([65564, 65524]).toContain(d2.length)
        })
      readStream.destroy()
    })
})
// Test Case 62: rearrangement, with editlist before, multiple header packets, for one new header packet
test('rearrangement, with editlist before, one header packet, for multiple new header packets', async () => {
  const editlist = [0, 5]
  const readStream = fs.createReadStream('Data4Tests/testcase25.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await crypt4GHJS.rearrangment.streamRearrange(Uint8Array.from(d), seckeyPass, [pubkey], editlist)
      await expect(rearrangeHeader[0]).toBeInstanceOf(Uint8Array)
      // fs.appendFileSync('Data4Tests/testcase62.c4gh', rearrangeHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase25.c4gh', { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('Data4Tests/testcase62.c4gh', d2)
          await expect([65564, 65524]).toContain(d2.length)
        })
      readStream.destroy()
    })
})
// Test Case 63: rearrangement, with editlist before, multiple header packets, for multiple new header packets
test('rearrangement, with editlist before, one header packet, for multiple new header packets', async () => {
  const editlist = [0, 5]
  const readStream = fs.createReadStream('Data4Tests/testcase25.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await crypt4GHJS.rearrangment.streamRearrange(Uint8Array.from(d), seckeyPass, [pubkey, pubkeyPass], editlist)
      await expect(rearrangeHeader[0]).toBeInstanceOf(Uint8Array)
      // fs.appendFileSync('Data4Tests/testcase63.c4gh', rearrangeHeader[0])
      const readStream2 = fs.createReadStream('Data4Tests/testcase25.c4gh', { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // fs.appendFileSync('Data4Tests/testcase63.c4gh', d2)
          await expect([65564, 65524]).toContain(d2.length)
        })
      readStream.destroy()
    })
})
// Test Case 64:rearrangement, with editlist before, new edit out of range (error)
test('rearrangement, with editlist before, one header packet, for multiple new header packets', async () => {
  const editlist = [0, 5]
  const readStream = fs.createReadStream('Data4Tests/testcase25.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await crypt4GHJS.rearrangment.streamRearrange(Uint8Array.from(d), seckeyPass, [pubkey], pubkeyPass, editlist)
      expect(rearrangeHeader).toBe(undefined)
      readStream.destroy()
    })
})
// decryption

// decryption of encryption

// Test Case 65: decryptin: encryption without additional parameters, single header packet
test('decryptin: encryption without additional parameters, single header packet', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase9.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase9.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase65.txt', plaintext)
          expect(plaintext).toBeInstanceOf(Uint8Array)
          await expect([65536,65496]).toContain(plaintext.length)
          const decoder = new TextDecoder()
        })
      readStream.destroy()
    })
}) 
// Test Case 66: decryptin: encryption with editlist even, single header packet
test('decryptin: encryption with editlist even, single header packet', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase10.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase10.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase66.txt', plaintext)
            await expect(plaintext).toBeInstanceOf(Uint8Array)
            const decoder = new TextDecoder()
            await expect(['faaaaaaaaa', 'bbbbb']).toContain(decoder.decode(plaintext))
          }
        })
      readStream.destroy()
    })
}) 
// Test Case 67: decryptin: encryption with editlist odd, single header packet
test('decryptin: encryption with editlist odd, single header packet', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase11.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase11.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase67.txt', plaintext)
            await expect(plaintext).toBeInstanceOf(Uint8Array)
            const decoder = new TextDecoder()
            await expect(['faaaa', 'ddddf']).toContain(decoder.decode(plaintext))
          }
        })
      readStream.destroy()
    })
}) 
// Test Case 68: decryptin: encryption with editlist just 1 number, single header packet
test('decryptin: encryption with editlist odd, single header packet', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase12.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase12.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase68.txt', plaintext)
            await expect(plaintext).toBeInstanceOf(Uint8Array)
            const decoder = new TextDecoder()
            await expect(['dddddddddf']).toContain(decoder.decode(plaintext))
          }
        })
      readStream.destroy()
    })
}) 
// Test Case 69: decryptin: encryption special case 1, single header packet
// Test Case 70: decryptin: encryption special case 2, single header packet
// Test Case 71: decryptin: encryption special case 3, single header packet
// Test Case 72: decryptin: encryption special case 4, single header packet
// Test Case 73: decryptin: encryption with blocks one block, single header packet
test('decryptin: encryption with blocks one block, single header packet', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase19.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase19.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase73.txt', plaintext)
            await expect(plaintext).toBeInstanceOf(Uint8Array)
            const decoder = new TextDecoder()
            await expect(plaintext.length).toBe(65536)
            await expect(decoder.decode(plaintext)).toMatch(/^f(a{65532})bbb$/)
          }
        })
      readStream.destroy()
    })
}) 
// Test Case 74: decryptin: encryption with blocks multiple block, single header packet
test('decryptin: encryption with blocks multiple block, single header packet', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase20.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase20.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase74.txt', plaintext)
            await expect(plaintext).toBeInstanceOf(Uint8Array)
            const decoder = new TextDecoder()
            await expect(plaintext.length).toBe(65536)
            await expect(decoder.decode(plaintext)).toMatch(/^f(a{65532})bbb|(d{65531})ffaaa$/)
          }
        })
      readStream.destroy()
    })
}) 

// Test Case 75: decryptin: encryption without additional parameters, multiple header packets
test('decryptin: encryption without additional parameters, multiple header packets seckey', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase24.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase24.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase75seckey.txt', plaintext)
          expect(plaintext).toBeInstanceOf(Uint8Array)
          await expect([65536,65496]).toContain(plaintext.length)
        })
      readStream.destroy()
    })
}) 

test('decryptin: encryption without additional parameters, multiple header packets seckeyPass', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase24.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckeyPass)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase24.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase75seckeyPass.txt', plaintext)
          expect(plaintext).toBeInstanceOf(Uint8Array)
          await expect([65536,65496]).toContain(plaintext.length)
        })
      readStream.destroy()
    })
}) 

// Test Case 76: decryptin: encryption with editlist even, multiple header packets
test('decryptin: encryption with editlist even, multiple header packets, seckey', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase25.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase25.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase76seckey.txt', plaintext)
            expect(plaintext).toBeInstanceOf(Uint8Array)
            await expect([10,5]).toContain(plaintext.length)
            const decoder = new TextDecoder()
            await expect(decoder.decode(plaintext)).toMatch(/^(b{5})|f(a{9})$/)
          }
        })
      readStream.destroy()
    })
}) 

test('decryptin: encryption with editlist even, multiple header packets seckeyPass', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase25.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckeyPass)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase25.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase76seckeyPass.txt', plaintext)
            expect(plaintext).toBeInstanceOf(Uint8Array)
            await expect([10,5]).toContain(plaintext.length)
            const decoder = new TextDecoder()
            await expect(decoder.decode(plaintext)).toMatch(/^(b{5})|f(a{9})$/)
          }
        })
      readStream.destroy()
    })
})

// Test Case 77: decryptin: encryption with editlist odd, multiple header packets
test('decryptin: encryption with editlist odd, multiple header packets, seckey', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase26.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase26.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase77seckey.txt', plaintext)
            expect(plaintext).toBeInstanceOf(Uint8Array)
            await expect([10,5]).toContain(plaintext.length)
            const decoder = new TextDecoder()
            await expect(decoder.decode(plaintext)).toMatch(/^f(a{4})|ddddf$/)
          }
        })
      readStream.destroy()
    })
}) 

test('decryptin: encryption with editlist odd, multiple header packets, seckeyPass', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase26.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckeyPass)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase26.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase77seckeyPass.txt', plaintext)
            expect(plaintext).toBeInstanceOf(Uint8Array)
            await expect([10,5]).toContain(plaintext.length)
            const decoder = new TextDecoder()
            await expect(decoder.decode(plaintext)).toMatch(/^f(a{4})|ddddf$/)
          }
        })
      readStream.destroy()
    })
})
// Test Case 78: decryptin: encryption with editlist just 1 number, multiple header packets
test('decryptin: encryption with editlist just 1 number, multiple header packets, seckey', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase27.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase27.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase78seckey.txt', plaintext)
            expect(plaintext).toBeInstanceOf(Uint8Array)
            await expect([10,5]).toContain(plaintext.length)
            const decoder = new TextDecoder()
            await expect(decoder.decode(plaintext)).toMatch(/^(d{9})f$/)
          }
        })
      readStream.destroy()
    })
}) 

test('decryptin: encryption with editlist just 1 number, multiple header packets, seckeyPass', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase27.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckeyPass)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase27.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase78seckeyPass.txt', plaintext)
            expect(plaintext).toBeInstanceOf(Uint8Array)
            await expect([10,5]).toContain(plaintext.length)
            const decoder = new TextDecoder()
            await expect(decoder.decode(plaintext)).toMatch(/^(d{9})f$/)
          }
        })
      readStream.destroy()
    })
})
// Test Case 79: decryptin: encryption special case 1, multiple header packets
// Test Case 80: decryptin: encryption special case 2, multiple header packets
// Test Case 81: decryptin: encryption special case 3, multiple header packets
// Test Case 82: decryptin: encryption special case 4, multiple header packets
// Test Case 83: decryptin: encryption with blocks one block, multiple header packets
test('decryptin: encryption with blocks one block, multiple header packets, seckey', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase34.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase34.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase83seckey.txt', plaintext)
            await expect(plaintext).toBeInstanceOf(Uint8Array)
            const decoder = new TextDecoder()
            await expect(plaintext.length).toBe(65536)
            await expect(decoder.decode(plaintext)).toMatch(/^f(a{65532})bbb$/)
          }
        })
      readStream.destroy()
    })
}) 

test('decryptin: encryption with blocks one block, multiple header packets, seckeyPass', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase34.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckeyPass)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase34.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            // fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase83seckeyPass.txt', plaintext)
            await expect(plaintext).toBeInstanceOf(Uint8Array)
            const decoder = new TextDecoder()
            await expect(plaintext.length).toBe(65536)
            await expect(decoder.decode(plaintext)).toMatch(/^f(a{65532})bbb$/)
          }
        })
      readStream.destroy()
    })
}) 
// Test Case 84: decryptin: encryption with blocks multiple block, multiple header packets
test('decryptin: encryption with blocks multiple block, multiple header packets, seckey', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase35.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckey)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase35.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase84seckey.txt', plaintext)
            await expect(plaintext).toBeInstanceOf(Uint8Array)
            const decoder = new TextDecoder()
            await expect(plaintext.length).toBe(65536)
            await expect(decoder.decode(plaintext)).toMatch(/^f(a{65532})bbb|(d{65531})ffaaa$/)
          }
        })
      readStream.destroy()
    })
}) 

test('decryptin: encryption with blocks multiple block, multiple header packets, seckeyPass', async () => {
  const wantedblocks = null
  const readStream = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase35.c4gh', { end: 1000 })
  readStream
    .on('data', async function (d) {
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), seckeyPass)
      await expect(val).toBeInstanceOf(Array)
      await expect(val[1]).toBeInstanceOf(Uint8Array)
      const readStream2 = fs.createReadStream('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase35.c4gh', { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const plaintext = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          if(plaintext){
            fs.appendFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/Data4Tests/testcase84seckeyPass.txt', plaintext)
            await expect(plaintext).toBeInstanceOf(Uint8Array)
            const decoder = new TextDecoder()
            await expect(plaintext.length).toBe(65536)
            await expect(decoder.decode(plaintext)).toMatch(/^f(a{65532})bbb|(d{65531})ffaaa$/)
          }
        })
      readStream.destroy()
    })
}) 
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
