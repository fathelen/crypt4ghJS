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
    const seckeyFile = await file.text()
    const block = blocks.split(',')
    const fileContents = document.getElementById('filecontents')
    const keys = await keyfiles.encryption_keyfiles([seckeyFile], password)
    const headerChunk = await file2.slice(0, 1000)
    const chunkHeader = await headerChunk.arrayBuffer()
    const header = decryption.header_deconstruction(new Uint8Array(chunkHeader), keys[0])
    const chunksize = 65564
    let offset = header[4]
    while (offset < file2.size) {
      const chunkfile = await file2.slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      const plaintext = decryption.pureDecryption(new Uint8Array(chunk), header[0], block)
      const decoder = new TextDecoder()
      fileContents.innerText += decoder.decode(plaintext)
      offset += chunksize
    }
    console.log('all done')
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
