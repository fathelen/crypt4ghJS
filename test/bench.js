/* eslint-disable indent */
/* eslint-disable eol-last */
/* eslint no-undef: */
import * as crypt4GHJS from 'crypt4gh_js'
import * as fs from 'fs'

//const ts = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAgrpd+v2ZGymbextTp5nMt298h1yEFBigB+bS+1WJT/lM=\n-----END CRYPT4GH PRIVATE KEY-----\n'
//const tp = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nfQCgFp/dPaDOELnzrgEEQUeOmOlMj9M/dTP7bIiuxyw=\n-----END CRYPT4GH PUBLIC KEY-----\n'
//const ts2 = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAErnfoX48n1p21KYPJF39qwARY2hhY2hhMjBfcG9seTEzMDUAPB2VckJsR/5iz35Zg5VO2VRkdIStoFIL0681lrdKlpn80dA7bH+vRcQc1+LVT4vptEt7EC5eXltE07uNhA==\n-----END CRYPT4GH PRIVATE KEY-----\n'
//const tp2 = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nKK2of4G9P49mpUE1PVDia+hTSQ8VWJNXxkSG4m6OiUc=\n-----END CRYPT4GH PUBLIC KEY-----\n'

async function encryption (input, seckeyPath, pubkeyPath, output, edit, blocks) {
  const seckey = fs.readFileSync(seckeyPath, {encoding: 'utf8'})
  const pubkey = fs.readFileSync(pubkeyPath, {encoding: 'utf-8'})
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey, pubkey], "passwort")
  const header = await crypt4GHJS.encryption.encHead(keys[0], [keys[1]], edit, blocks)
  //process.stdout.write(header[0])
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

//encryption('../testData/32kb', '../testData/alice.sec', '../testData/bob.pub', '../testData/32kb.c4gh')

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

//pureWriting('../testData/1gb')

//const seckeyPass = new Uint8Array([ 239,  53, 227, 105, 157, 144,  90, 226, 118, 104,  90,  48,  37,  89,  73, 246, 10, 150, 243, 176, 181,  40, 210,  96, 102, 181, 168,  18,  59, 126, 206,  33 ])

async function decryption (input, seckeyPath, output, wantedblocks) {
  const seckey = fs.readFileSync(seckeyPath, {encoding: 'utf8'})
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey], 'passwort')
  const readStream = fs.createReadStream(input, { end: 10000 })
  const writeStream = fs.createWriteStream(output)
  readStream
    .on('data', async function (d) {
    //process.stdout.write('')
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
            writeStream.write(text)
            //process.stdout.write(text)
            //fs.appendFile(output, text, (err) => {
              //if (err) {
                //console.log(err)
              //}
            //})
          } 
        }) 
        .on('end', (d2) => {
          readStream2.destroy()
          readStream.destroy()
         })
    })
}

//decryption('../testData/32kb.c4gh', '../testData/bob.sec','../testData/32kbdec')

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

async function encryptionEditlist (input, seckeyPath, pubkeyPath, output, edit, blocks) {
  const seckey = fs.readFileSync(seckeyPath, {encoding: 'utf8'})
  const pubkey = fs.readFileSync(pubkeyPath, {encoding: 'utf-8'})
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey, pubkey])
  const header = await crypt4GHJS.encryption.encHead(keys[0], [keys[1]], edit, blocks)
  //process.stdout.write(header[0])
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

//encryptionEditlist('../testData/21541_1#4.cram', '../testData/ts', '../testData/tp', '../testData/cramblock.c4gh', [140000,30])

async function decryptionEditlist (input, seckeyPath, output, wantedblocks) {
  const seckey = fs.readFileSync(seckeyPath, {encoding: 'utf8'})
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey])
  const readStream = fs.createReadStream(input, { end: 10000 })
  readStream
    .on('data', async function (d) {
    //process.stdout.write('')
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
            //process.stdout.write(text)
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

//decryptionEditlist('../testData/cramblock.c4gh', '../testData/ts','../testData/cramdec')