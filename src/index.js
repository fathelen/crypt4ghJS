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
  const result = keygen.keygen(password)
  const erg = await result
  const pubkey = document.getElementById('pubkeyfile')
  pubkey.innerText = erg[1]
  const seckey = document.getElementById('seckeyfile')
  seckey.innerText = erg[0]
})

// Encryption
document.getElementById('input2').addEventListener('change', function (e) {
  const file = document.getElementById('input2').files[0]
  const file3 = document.getElementById('input2').files[1]
  const file4 = document.getElementById('input2').files[2]
  const password = document.getElementById('psw3').value
  const blocks = document.getElementById('block2').value
  const edit = document.getElementById('block3').value;

  (async () => {
    const pubkeyFile = await file.text()
    const seckeyFile = await file3.text()
    const block = blocks.split(',')
    let editlist = []
    if (edit.includes(';')) {
      const step = edit.split(';')
      for (let i = 0; i < step.length; i++) {
        editlist.push(step[i].split(','))
      }
    } else {
      editlist = edit.split(',')
    }
    const fileContents = document.getElementById('encfile')
    const keys = await keyfiles.encryption_keyfiles([seckeyFile, pubkeyFile], password)
    const header = encryption.encHeader(keys[0], [keys[1]], block, editlist)
    fileContents.innerText += header
    const chunksize = 65536
    let offset = 0
    while (offset < file4.size) {
      const chunkfile = await file4.slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      const encryptedtext = await encryption.pureEncryption(new Uint8Array(chunk), header[1])
      const encoder = new TextEncoder()
      fileContents.innerText += encoder.encode(encryptedtext)
      offset += chunksize
    }
    console.log('all done')
    /*
    const encryptedtext = await encryption(file4, keys[0], [keys[1], keys[2]], block, editlist)
    fileContents.innerText = encryptedtext */
  })()
})
