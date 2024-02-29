/* eslint-disable indent */
/* eslint-disable eol-last */
/* eslint no-undef: */
import * as crypt4GHJS from 'crypt4gh_js'
// const index = require('crypt4gh_js')
import * as fs from 'fs'
// const fs = require('fs')

const ts = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAgrpd+v2ZGymbextTp5nMt298h1yEFBigB+bS+1WJT/lM=\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nfQCgFp/dPaDOELnzrgEEQUeOmOlMj9M/dTP7bIiuxyw=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const ts2 = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAErnfoX48n1p21KYPJF39qwARY2hhY2hhMjBfcG9seTEzMDUAPB2VckJsR/5iz35Zg5VO2VRkdIStoFIL0681lrdKlpn80dA7bH+vRcQc1+LVT4vptEt7EC5eXltE07uNhA==\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp2 = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nKK2of4G9P49mpUE1PVDia+hTSQ8VWJNXxkSG4m6OiUc=\n-----END CRYPT4GH PUBLIC KEY-----\n'

async function encryption (input, output, edit, blocks) {
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([ts, tp])
  const header = await crypt4GHJS.encryption.encHead(keys[0], [keys[1]], edit)
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
            // process.stdout.write(text)
            writeStream.write(text)
            }
          })
          .on('end', (d) => {
           writeStream.end()
          })
  }
}

// encryption('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd.txt', '/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd_edit.c4gh',[0, 5])

async function decryption (input, output, wantedblocks) {
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([ts])
  const readStream = fs.createReadStream(input, { end: 10000 })
  readStream
    .on('data', async function (d) {
      fs.writeFile(output, '', (err) => {
        if (err) {
          console.log(err)
        }
      })
      let counter = 0
      const val = await crypt4GHJS.decryption.headerDeconstruction(Uint8Array.from(d), keys[0])
      const readStream2 = fs.createReadStream(input, { start: val[4], highWaterMark: 65564 })
      readStream2
        .on('data', async function (d2) {
          counter++
          const text = await crypt4GHJS.decryption.decrypption(val, d2, counter, wantedblocks)
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

decryption('testData/testEdit.c4gh', 'testData/testEdit.txt')

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

// generateKeys('testData/abcd_editRE.c4gh', 'testData/pubkey', 'aaa')

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

// reencryption('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd_edit.c4gh', 'testData/testEdit.c4gh')

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

// rearrangement('/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcd.c4gh', '/home/fabienne/Projects/Crypt4ghJSCode/crypt4ghJS/testData/abcdREA.c4gh')