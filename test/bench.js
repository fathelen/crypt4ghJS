/* eslint-disable indent */
/* eslint-disable eol-last */
/* eslint no-undef: */
const index = require('crypt4gh_js')
const fs = require('fs')
// const { Transform } = require('stream')
// const { pipeline } = require('stream')

// const data = fs.readFileSync('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/testfile_abcd.txt')
// const secret = Uint8Array.from([174, 151, 126, 191, 102, 70, 202, 102, 222, 198, 212, 233, 230, 115, 45, 219, 223, 33, 215, 33, 5, 6, 40, 1, 249, 180, 190, 213, 98, 83, 254, 83])
// const ppublic = Uint8Array.from([125, 0, 160, 22, 159, 221, 61, 160, 206, 16, 185, 243, 174, 1, 4, 65, 71, 142, 152, 233, 76, 143, 211, 63, 117, 51, 251, 108, 136, 174, 199, 44])
// const pubkey = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nGER04WfJXzPHiCWe94CHlMY6sp6zwWpAehA0MMHjdVQ=\n-----END CRYPT4GH PUBLIC KEY-----\n'
// const seckey = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAg4BW6LpwKHBQN0MCZgjPtDafcGbN5wRmUSrIwEcN4te0=\n-----END CRYPT4GH PRIVATE KEY-----\n'
// const sessionkey = Uint8Array.from([57, 108, 121, 106, 108, 112, 99, 101, 112, 98, 115, 112, 50, 111, 109, 49, 111, 113, 102, 52, 100, 55, 120, 50, 113, 109, 117, 119, 102, 120, 115, 97])
const ts = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAgrpd+v2ZGymbextTp5nMt298h1yEFBigB+bS+1WJT/lM=\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nfQCgFp/dPaDOELnzrgEEQUeOmOlMj9M/dTP7bIiuxyw=\n-----END CRYPT4GH PUBLIC KEY-----\n'
// 224,  21, 186,  46, 156,  10,  28,  20,13, 208, 192, 153, 130,  51, 237,  13,167, 220,  25, 179, 121, 193,  25, 148, 74, 178,  48,  17, 195, 120, 181, 237
// shared 169, 178,  46, 162, 139, 217, 227, 152,34, 183, 130, 147,  49,  57,  20,  26,74, 245, 236,  70, 222, 144, 219,  36,62, 181, 186, 132,  12, 199, 255, 169

/*
async function encryption (input, output) {
  const keys = await index.keyfiles.encryption_keyfiles([ts, tp])
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
*/

async function decryption (input, output) {
  const keys = await index.keyfiles.encryption_keyfiles([ts])
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