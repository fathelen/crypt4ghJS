const { parentPort, workerData } = require('worker_threads')
const fs = require('fs')
const index = require('crypt4gh_js')

/*
const { file } = workerData
const output = `${file}.encrypted`
const key = crypto.randomBytes(32)
const iv = crypto.randomBytes(16)
const cipher = crypto.createCipheriv('aes-256-ctr', Buffer.from(key), iv)
const readStream = fs.createReadStream(file)
const writeStream = fs.createWriteStream(output)
readStream.pipe(cipher).pipe(writeStream)
writeStream.on('close', () => parentPort.postMessage({ key: key.toString('hex'), output, type: 'done' }))
*/

const ts = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAgrpd+v2ZGymbextTp5nMt298h1yEFBigB+bS+1WJT/lM=\n-----END CRYPT4GH PRIVATE KEY-----\n'
const tp = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nfQCgFp/dPaDOELnzrgEEQUeOmOlMj9M/dTP7bIiuxyw=\n-----END CRYPT4GH PUBLIC KEY-----\n'
/*
async function encryption (edit, blocks) {
  const input = Object.values(workerData)[0]
  const output = `${input}.encrypted`
  const keys = await index.keyfiles.encryption_keyfiles([ts, tp])
  const header = await index.encryption.encHead(keys[0], [keys[1]], edit)
  // process.stdout.write(header[0])
  const writeStream = fs.createWriteStream(output)
  writeStream.write(header[0])
  /* fs.writeFile(output, header[0], (err) => {
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
          // process.stdout.write(text)
          writeStream.write(text)
          // readStream.pipe(text).pipe(writeStream)
          /*
                fs.appendFile(output, text, (err) => {
                  if (err) {
                    console.log(err)
                  }
                })
        }
      })
      .on('end', (d) => {
        writeStream.end(() => parentPort.postMessage({ key: keys.toString('hex'), output, type: 'done' }))
        // breakPoint()
      })
  }
} */

async function encryption (edit, blocks) {
  const output = 'testData/abcd.c4gh'
  const input = Object.values(workerData)
  const d = input[0]
  const counter = input[1]
  const header = input[2]
  const keys = input[3]
  const writeStream = fs.createWriteStream(output, { flags: 'a' })
  const text = await index.encryption.encryption(header, d, counter, blocks)
  if (text) {
    writeStream.write(text)
  }
  writeStream.end(() => parentPort.postMessage({ key: keys.toString('hex'), output, type: 'done' }))
}

encryption()
