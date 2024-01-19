/* eslint-disable indent */
/* eslint-disable eol-last */
/* eslint no-undef: */
const index = require('crypt4gh_js')
const fs = require('fs')

const ts = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAgrpd+v2ZGymbextTp5nMt298h1yEFBigB+bS+1WJT/lM=\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nfQCgFp/dPaDOELnzrgEEQUeOmOlMj9M/dTP7bIiuxyw=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const pubkeyPass = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nvHrVpBpFLpX/OquK2Ze4Mfzb8aVrn05XmTgT4ymVwzE=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const seckeyPass = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAMHZyZm0wb3JrM2E5d2QyeQARY2hhY2hhMjBfcG9seTEzMDUAPHUyY2lhbDQ1dWZydxzqFWikrPHQc6dKqWySS59BoMAe1L0FRmBXnwPd80N4fJBJS5f+vnmlA+JZ8qCpow==\n-----END CRYPT4GH PRIVATE KEY-----\n'
const ptest = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nN63bgz4c9GZaadtWjYGAlGMvFTHGSyVZO/Setcb7KGE=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const stest = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAYoz9LwYFw4LUzvWleuruQwARY2hhY2hhMjBfcG9seTEzMDUAPJ7bIhilIbds1B8Mx7ItNJ6jwlmXv/6nFnE3zeQVaHDoGZ3b0lKQcVMrE9SKneSdOhKjlZxqzDcdztde8w==\n-----END CRYPT4GH PRIVATE KEY-----\n'
const ts2 = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAErnfoX48n1p21KYPJF39qwARY2hhY2hhMjBfcG9seTEzMDUAPB2VckJsR/5iz35Zg5VO2VRkdIStoFIL0681lrdKlpn80dA7bH+vRcQc1+LVT4vptEt7EC5eXltE07uNhA==\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp2 = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nKK2of4G9P49mpUE1PVDia+hTSQ8VWJNXxkSG4m6OiUc=\n-----END CRYPT4GH PUBLIC KEY-----\n'
async function encryption (input, output, edit, blocks) {
  const keys = await index.keyfiles.encryption_keyfiles([ts2, tp2], 'abc')
  const header = await index.encryption.encHead(keys[0], [keys[1]], edit)
    fs.writeFile(output, header[0], (err) => {
      if (err) {
        console.log(err)
      }
    })
   if (header[1]) {
    let counter = 0
      const readStream = fs.createReadStream(input)
        readStream
          .on('data', async function (d) {
            counter++
            const text = await index.encryption.encryption(header, d, counter, blocks)
            if (text) {
              fs.appendFile(output, text, (err) => {
                if (err) {
                  console.log(err)
                }
              })
            }
          })
  }
}

// encryption('/home/fabienne/Projects/test.txt', '/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/keytest.c4gh')

async function decryption (input, output, wantedblocks) {
  const keys = await index.keyfiles.encryption_keyfiles([ts2], 'abc')
  const readStream = fs.createReadStream(input, { end: 1000 })
  readStream
    .on('data', async function (d) {
      fs.writeFile(output, '', (err) => {
        if (err) {
          console.log(err)
        }
      })
      let counter = 0
      const val = await index.decryption.header_deconstruction(Uint8Array.from(d), keys[0])
      const readStream2 = fs.createReadStream(input, { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const text = await index.decryption.decrypption(val, d2, counter, wantedblocks)
          if (text) {
            fs.appendFile(output, text, (err) => {
              if (err) {
                console.log(err)
              }
            })
          }
        })

      readStream.destroy()
    })
}

decryption('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/keytest.c4gh', '/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/downloadTest.txt')

async function generateKeys (password) {
   const keys = await index.keygen.keygen(password)
   console.log(keys[0])
   console.log(keys[1])
}

// generateKeys('abc')

// Reencryption
async function reencryption (input, output) {
  const keys = await index.keyfiles.encryption_keyfiles([ts, tp])
  const readStream = fs.createReadStream(input, { end: 1000 })
  readStream
    .on('data', async function (d) {
      const reencryptHeader = await index.reeencryption.streamReencryptHeader(Uint8Array.from(d), [keys[1]], keys[0])
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

// reencryption('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd_multi_multiedit.c4gh', '/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd_reenc_edit.c4gh')

// Rearrangement
async function rearrangement (input, output) {
  const keys = await index.keyfiles.encryption_keyfiles([ts, tp, pubkeyPass])
  const editlist = [[0, 1], [0, 2]]
  const readStream = fs.createReadStream(input, { end: 1000 })
  readStream
    .on('data', async function (d) {
      const rearrangeHeader = await index.rearrangment.streamRearrange(Uint8Array.from(d), keys[0], [keys[1], keys[2]], editlist)
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

// rearrangement('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd_multi_multiedit.c4gh', '/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd_rearr_multiedit.c4gh')