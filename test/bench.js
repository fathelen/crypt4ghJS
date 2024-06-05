/* eslint-disable indent */
/* eslint-disable eol-last */
/* eslint no-undef: */
import * as crypt4GHJS from 'crypt4gh_js'
import * as fs from 'fs'
import _sodium from 'libsodium-wrappers'
import * as Blake2b from '@stablelib/blake2b'
import * as x25519 from '@stablelib/x25519'


const ts = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAgrpd+v2ZGymbextTp5nMt298h1yEFBigB+bS+1WJT/lM=\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nfQCgFp/dPaDOELnzrgEEQUeOmOlMj9M/dTP7bIiuxyw=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const ts2 = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAErnfoX48n1p21KYPJF39qwARY2hhY2hhMjBfcG9seTEzMDUAPB2VckJsR/5iz35Zg5VO2VRkdIStoFIL0681lrdKlpn80dA7bH+vRcQc1+LVT4vptEt7EC5eXltE07uNhA==\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp2 = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nKK2of4G9P49mpUE1PVDia+hTSQ8VWJNXxkSG4m6OiUc=\n-----END CRYPT4GH PUBLIC KEY-----\n'

async function encryption (input, seckeyPath, pubkeyPath, output, edit, blocks) {
  const seckey = fs.readFileSync(seckeyPath, {encoding: 'utf8'})
  const pubkey = fs.readFileSync(pubkeyPath, {encoding: 'utf-8'})
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey, pubkey], "passwort")
  const header = await crypt4GHJS.encryption.encHead(keys[0], [keys[1]], edit, blocks)
  // process.stdout.write(header[0])
  const writeStream = fs.createWriteStream(output)
  writeStream.write(header[0])
   if (header[1]) {
    let counter = 0
    const readStream = fs.createReadStream(input)
      readStream
        .on('data', async function (d) {
          counter++
          const text = await crypt4GHJS.encryption.encryption(header, d, counter, blocks)
          if (text) {
            //process.stdout.write(text)
            writeStream.write(text)
            }
          })
          .on('end', (d) => {
            writeStream.end()
            readStream.destroy()
          })
  }
}

// encryption('../testData/32kb', '../test/passwort_sec', '../test/passwort_pub', '../test/edit8',[70000,5,60000,2000])

async function pureWriting (input, output, edit, blocks) {
    const readStream = fs.createReadStream(input)
      readStream
        .on('data', async function (d) {
          process.stdout.write(d)
        })
        .on('end', (d) => {
          readStream.destroy()
         })
}

// pureWriting('../testData/1gb')

const seckeyPass = new Uint8Array([ 239,  53, 227, 105, 157, 144,  90, 226, 118, 104,  90,  48,  37,  89,  73, 246, 10, 150, 243, 176, 181,  40, 210,  96, 102, 181, 168,  18,  59, 126, 206,  33 ])

async function decryption (input, seckeyPath, output, wantedblocks) {
  const seckey = fs.readFileSync(seckeyPath, {encoding: 'utf8'})
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey], 'passwort')
  const readStream = fs.createReadStream(input, { end: 10000 })
  readStream
    .on('data', async function (d) {
      // process.stdout.write('')
      fs.writeFile(output, '', (err) => {
        if (err) {
          console.log(err)
        }
      })
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), keys[0])
      /*
      console.log('header: ', val)
      const readStream2 = fs.createReadStream(input, { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const text = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
          console.log('text: ',text)
          if (text) {
            // process.stdout.write(text)
            fs.appendFile(output, text, (err) => {
              if (err) {
                console.log(err)
              }
            })
          } 
        }) */

      readStream.destroy()
    })
}

decryption('../test/edit8', '../test/passwort_sec','../test/edit8_decryption')

async function c4ghWriting (input, output, wantedblocks) {
  const readStream = fs.createReadStream(input)
  readStream
    .on('data', async function (d) {
      process.stdout.write(d)
    })
    .on('end', (d) => {
      readStream.destroy()
     })
}

// c4ghWriting('../testData/1gb.c4gh')

async function generateKeys (secFile, pubFile, password) {
   const keys = await crypt4GHJS.keygen.keygen(password)
   fs.writeFile(secFile, keys[0], (err) => {
    if (err) {
      console.log(err)
    }
  })
  fs.writeFile(pubFile, keys[1], (err) => {
    if (err) {
      console.log(err)
    }
  })
}

// generateKeys('abcd_sec', 'abcd_pub', 'passwort')


// Reencryption
async function reencryption (input, output) {
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([ts, tp])
  const readStream = fs.createReadStream(input, { end: 10000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = await crypt4GHJS.reeencryption.streamReencryptHeader(Uint8Array.from(d), [keys[1]], keys[0])
      fs.writeFile(output, reencryptHeader[0], (err) => {
        if (err) {
          console.log(err)
        }
      })
      const readStream2 = fs.createReadStream(input, { start: reencryptHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          fs.appendFile(output, d2, (err) => {
            if (err) {
              console.log(err)
            }
          })
        })
      readStream.destroy()
    }) 
}

// reencryption('../testData/abcd_edit.c4gh', '../testData/testEdit.c4gh')

// Rearrangement
async function rearrangement (input, output) {
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([ts, tp, tp2])
  const editlist = [[0, 1], [0, 2]]
  const readStream = fs.createReadStream(input, { end: 10000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await crypt4GHJS.rearrangment.streamRearrange(Uint8Array.from(d), keys[0], [keys[1], keys[2]], editlist)
      fs.writeFile(output, rearrangeHeader[0], (err) => {
        if (err) {
          console.log(err)
        }
      })
      const readStream2 = fs.createReadStream(input, { start: rearrangeHeader[1], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          fs.appendFile(output, d2, (err) => {
            if (err) {
              console.log(err)
            }
          })
        })
      readStream.destroy()
    })
}

// rearrangement('../testData/abcd.c4gh', '../testData/abcdREA.c4gh')
const fixkey_sec = new Uint8Array([ 239,  53, 227, 105, 157, 144,  90, 226, 118, 104,  90,  48,  37,  89,  73, 246, 10, 150, 243, 176, 181,  40, 210,  96, 102, 181, 168,  18,  59, 126, 206,  33 ])
const fixkey_pub = new Uint8Array([ 185, 166, 222, 208,  72, 148, 218, 76,  96,  57,  73, 228, 246,  63, 197, 247,  81, 153, 179, 159, 209, 169, 105, 116, 255, 125, 223, 244, 119, 168, 113,   9])  

const ts_pass = new Uint8Array([
  83, 227, 216,  91, 236, 244,  79, 139,
 143, 177,  91,  43,  90, 135, 138, 213,
 130, 226,   4, 156, 205, 178, 179,  50,
 124,  33, 235,   2, 159, 116, 237, 122
])

const tp_pass = new Uint8Array([
  239, 154,  37, 168, 165,  34, 165,  82,
  205, 138, 185, 156, 205,  37, 234, 200,
  155, 187, 100,  67, 117, 184,  36,  82,
  244,  37, 111, 198,  59,  14, 136,  50
])


async function Enc_Frank (key, fix_sec) {
  let encData = new Uint8Array()
  let secret
  let x
  await (async () => {
    await _sodium.ready
    const sodium = _sodium
    let sec = sodium.randombytes_buf(12)
    let nonce = sodium.randombytes_buf(12)
    const blake2b = new Blake2b.BLAKE2b()
    blake2b.update(sec)
    secret = blake2b.digest()
    console.log('secret: ', secret)
    const sharedkey = x25519.sharedKey(fix_sec, key)
    encData = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(sec, null, null, nonce, sharedkey)
    const decNonce = Buffer.concat([nonce, encData])
    x = new Uint8Array(decNonce)
  })()
  return x
}

// const de = await Enc_Frank(tp_pass, fixkey_sec)
// console.log(de)


