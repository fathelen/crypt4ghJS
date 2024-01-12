const keygen = require('./keygen')
const keyfiles = require('./check_keyfiles')
const encryption = require('./encryption')
const decryption = require('./decryption')
const reeencryption = require('./reeencryption')
const rearrangment = require('./rearrange')
const checkFileformat = require('./check_fileformat')

// Decryption

document.getElementById('input').addEventListener('change', function (e) {
  const file = document.getElementById('input').files[0]
  const file2 = document.getElementById('input').files[1]
  const password = document.getElementById('psw').value
  const blocks = document.getElementById('block').value;
  (async () => {
    /*
    const seckeyFile = await file.text()
    const keys = await keyfiles.encryption_keyfiles([seckeyFile], password)
    const fileContents = document.getElementById('filecontents')
    fileContents.innerText = keys */
    const seckeyFile = await file.text()
    const block = blocks.split(',')
    const fileContents = document.getElementById('filecontents')
    const keys = await keyfiles.encryption_keyfiles([seckeyFile], password)
    // const stream = file2.stream()
    const headerChunk = await file2.slice(0, 1000)
    const chunkHeader = await headerChunk.arrayBuffer()
    console.log(chunkHeader)
    console.log(keys[0])
    console.log(new Uint8Array(chunkHeader))
    const header = decryption.header_deconstruction(new Uint8Array(chunkHeader), keys[0])
    fileContents.innerText = header
    /*
    const chunksize = 65536
    let offset = 0
    while (offset < file2.size) {
      const chunkfile = await file2.slice(offset, offset + chunksize)
      // Blob.arrayBuffer() can be polyfilled with a FileReader
      const chunk = await chunkfile.arrayBuffer()
      const val = decryption.header_deconstruction(Uint8Array.from(chunk), keys[0])
      console.log(val)
      fileContents.innerText = val
      console.log('chunk: ', chunk)
      const plaintext = decryption.pureDecryption(file2, keys[0], block)
      console.log(plaintext)
      fileContents.innerText = plaintext
      offset += chunksize
    }
    console.log('all done')
    /*
    const reader = stream.getReader()
    while (true) {
      const chunk = await reader.readBytes(65536)
      if (chunk === undefined) {
        break
      }
      console.log(chunk.length)
      const plaintext = decryption.pureDecryption(chunk, keys[0], block)
      console.log(plaintext)
      fileContents.innerText = plaintext
    }
    console.log('all done')

    const plaintext = await decryption.pureDecryption(file2, keys[0], block)
    console.log(plaintext)
    fileContents.innerText = plaintext */
  })()
})

// KeyGen
const button = document.getElementById('submit')
button.addEventListener('click', async function (event) {
  const password = await document.getElementById('psw2').value
  console.log('password: ', password)
  const result = keygen.keygen(password)
  const erg = await result
  const pubkey = document.getElementById('pubkeyfile')
  pubkey.innerText = erg[1]
  const seckey = document.getElementById('seckeyfile')
  seckey.innerText = erg[0]
})
