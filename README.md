# Crypt4GH-JS 

Crypt4GH-JS is a JavaScript implementation of the standard file container format crypt4GH from the Global Alliance for Genomics and Health (GA4GH).
Crypt4GH was developed to ensure secured storing and sharing of sensitive data. 

Crypt4GH-JS has been implemented in JavaScript and is therefore applicable to all contemporary browser systems and offers all the prescribed parameters developed for Crypt4GH by the GA4GH.

## Installation 
crypt4GH-JS can be installated via the crypt4gh_js npm package and the crypt4ghJS GitHub repository. 
### Installation with npm: 
The npm package can be found here: [crypt4GH-JS](https://www.npmjs.com/package/crypt4gh_js) <br>
To install crypt4GH_JS via npm use:
```sh

npm i crypt4gh_js

```

 
 ### Installation from git: 
 To use the latest GitHub source install the package via: 
 ```sh

git clone https:https://github.com/fathelen/crypt4ghJS
npm i ./crypt4ghJS

```
 


## Usage 
The usage of the diffrent task, that can be handled via crypt4GH_JS, are shown in  the [example node file](https://github.com/fathelen/crypt4ghJS/blob/master/test/bench.js) <br>
and in the [example web file](https://github.com/fathelen/crypt4ghJS/blob/master/src/index.js) <br>
The single tasks will be explained in the following: <br>

### Generate keys 
The [crypt4GH specification](http://samtools.github.io/hts-specs/crypt4gh.pdf) prescribes the format of the keypair, that can be used for crypt4GH files. <br>
The format has to be like: <br>
 ```text

-----BEGIN CRYPT4GH PUBLIC KEY-----
Sw8o+Bpejno2FkDq23D2Q6GAOzq7Zy5a+brAqEgavEE=
-----END CRYPT4GH PUBLIC KEY-----

-----BEGIN CRYPT4GH PRIVATE KEY-----
YzRnaC12MQAGc2NyeXB0ABQAAAAAxr0v09Ec5NDcYKA7Ez4R5AARY2hhY2hhMjBfcG9seTEzMDUAPEfrI78aV6HMW78I51HwqMcPXyoqUACg0PQ4pijMGmlHMwjLdj5s8c3mjSR4MKjMQ6tkP5wT3KiOdKgxsQ==
-----END CRYPT4GH PRIVATE KEY-----
```
The function 'keygen' computes keyfiles in the given format.

For node:
 ```javascript

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

generateKeys('secret_key_file', 'public_key_file', 'passwort')

```
For web use: 
 ```javascript

async function keyfile () {
  const password = await document.getElementById('psw').value
  const result = await crypt4GHJS.keygen.keygen(password)
  return result
}

```
### Check keyfiles 
The function check keyfiles, is used to first check if the given keys are crypt4GH keys and second to decrypt the keys, to use them in the next step e.g. encryption or decryption. <br>
For node: 
 ```javascript
const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckeyFile, pubkeyFile], password)



```
As for web use: 
 ```javascript

const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckeyFile, pubkeyFile], password)

```
### Encrypt data 
For the crypt4GH encryption of data, 2 functions are needed. The first function 'encHead' is used to encrypt the header, the second function 'encryption' is used to encrypt the data.  <br>
For node: 
 ```javascript
async function encryption (input, seckeyPath, pubkeyPath, output, edit, blocks) {
  const seckey = fs.readFileSync(seckeyPath, {encoding: 'utf8'})
  const pubkey = fs.readFileSync(pubkeyPath, {encoding: 'utf-8'})
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey, pubkey])
  const header = await crypt4GHJS.encryption.encHead(keys[0], [keys[1]], edit, blocks)
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
            riteStream.write(text)
            }
          })
          .on('end', (d) => {
            writeStream.end()
          })
  }
}

encryption('data', 'secret_key_file', 'public_key_file' )

```
For web use: 
 ```javascript

 const seckeyFile = await file.files[0].text()
  const pubkeyFile = await file2.files[0].text()
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckeyFile, pubkeyFile], password)
  const header = await crypt4GHJS.encryption.encHead(keys[0], [keys[1]], ed, block)
  c4ghtext.push(header[0])
  const chunksize = 65536
  let counter = 0
  let offset = 0
  if (enteredText !== '') {
    while (offset < enteredText.length) {
      counter++
      const chunkfile = await enteredText.slice(offset, offset + chunksize)
      const encryptedtext = await crypt4GHJS.encryption.encryption(header, Uint8Array.from(chunkfile.split('').map(x => x.charCodeAt())), counter, block)
      if (encryptedtext) {
        c4ghtext.push(encryptedtext)
      }

      offset += chunksize
    }
  } else {
    while (offset < file3.files[0].size) {
      counter++
      const chunkfile = await file3.files[0].slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      const encryptedtext = await crypt4GHJS.encryption.encryption(header, new Uint8Array(chunk), counter, block)
      if (encryptedtext) {
      // yield encryptedtext
        c4ghtext.push(encryptedtext)
      }

      offset += chunksize
    }
  }

```

### Decrypt data
For the crypt4GH decryption again 2 functions are needed. The first function 'headerDeconstruction' is used to decrypt the header, the second function 'decryption' is used to decrypt the data.  <br>

For node: 
 ```javascript
async function decryption (input, seckeyPath, output, wantedblocks) {
  const seckey = fs.readFileSync(seckeyPath, {encoding: 'utf8'})
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckey])
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

// decryption('c4gh_file', 'secret_key_file')

```
For web use: 
 ```javascript

async function * decr () {
  let decText = ''
  const file = document.getElementById('input4')
  const file2 = document.getElementById('input5')
  let password = document.getElementById('psw3').value
  const seckeyFile = await file.files[0].text()
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckeyFile], password)
  const headerChunk = await file2.files[0].slice(0, 1000)
  const chunkHeader = await headerChunk.arrayBuffer()
  const header = await crypt4GHJS.decryption.headerDeconstruction(new Uint8Array(chunkHeader), keys[0])
  const chunksize = 65564
  let counter = 0
  let offset = header[4]
  while (offset < file2.files[0].size) {
    counter++
    const chunkfile = await file2.files[0].slice(offset, offset + chunksize)
    const chunk = await chunkfile.arrayBuffer()
    const plaintext = await crypt4GHJS.decryption.decrypption(header, new Uint8Array(chunk), counter)
    const decoder = new TextDecoder()
    if (plaintext) {
      decText += decoder.decode(plaintext)
      yield decText
    }
    offset += chunksize
  }
}

```


## Demonstration
For demonstration we build a  [Demo Website](https://fathelen.github.io/crypt4ghJS/)

## Crypt4GH Specification 

referring to: [crypt4GH specification](http://samtools.github.io/hts-specs/crypt4gh.pdf)

