/* eslint-disable indent */
/* eslint-disable eol-last */
/* eslint no-undef: */
const index = require('crypt4gh_js')
const fs = require('fs')
// const { Transform } = require('stream')
// const { pipeline } = require('stream')

const ts = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAgrpd+v2ZGymbextTp5nMt298h1yEFBigB+bS+1WJT/lM=\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nfQCgFp/dPaDOELnzrgEEQUeOmOlMj9M/dTP7bIiuxyw=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const pubkeyPass = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nvHrVpBpFLpX/OquK2Ze4Mfzb8aVrn05XmTgT4ymVwzE=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const seckeyPass = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAMHZyZm0wb3JrM2E5d2QyeQARY2hhY2hhMjBfcG9seTEzMDUAPHUyY2lhbDQ1dWZydxzqFWikrPHQc6dKqWySS59BoMAe1L0FRmBXnwPd80N4fJBJS5f+vnmlA+JZ8qCpow==\n-----END CRYPT4GH PRIVATE KEY-----\n'

async function encryption (input, output) {
  const keys = await index.keyfiles.encryption_keyfiles([seckeyPass, pubkeyPass], 'gunpass')
  edit = null
  block = null
  const header = index.encryption.encHeader(keys[0], [keys[1]], block, edit)
  fs.writeFile(output, header[0], (err) => {
    if (err) {
      console.log(err)
    }
  })
  if (header[1]) {
      const readStream = fs.createReadStream(input)
        readStream
          .on('data', async function (d) {
            const val = index.encryption.pureEncryption(d, header[1])
            fs.appendFile(output, val, (err) => {
              if (err) {
                console.log(err)
              }
            })
          })
  }
}

encryption('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd.txt', '/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd.c4gh')

/*
async function decryption (input, output) {
  const keys = await index.keyfiles.encryption_keyfiles([seckeyPass], 'gunpass')
  const readStream = fs.createReadStream(input, { end: 1000 })
  readStream
    .on('data', async function (d) {
      fs.writeFile(output, '', (err) => {
        if (err) {
          console.log(err)
        }
      })
      const val = index.decryption.header_deconstruction(Uint8Array.from(d), keys[0])
      const readStream2 = fs.createReadStream(input, { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          // console.log(Uint8Array.from(d2))
          const plaintext = await index.decryption.pureDecryption(Uint8Array.from(d2), val[0])
          fs.appendFile(output, plaintext, (err) => {
            if (err) {
              console.log(err)
            }
          })
        })
      readStream.destroy()
    })
}

decryption('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd.c4gh', '/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/Re_abcd.txt')
/*
async function generateKeys (password) {
   await index.keygen.keygen(password)
}

console.log(generateKeys('password')) */