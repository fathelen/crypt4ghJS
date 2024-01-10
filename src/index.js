const keygen = require('./keygen')
const keyfiles = require('./check_keyfiles')
const encryption = require('./encryption')
const decryption = require('./decryption')
const reeencryption = require('./reeencryption')
const rearrangment = require('./rearrange')
const checkFileformat = require('./check_fileformat')

module.exports = { keygen, keyfiles, encryption, decryption, reeencryption, rearrangment, check_fileformat: checkFileformat }

// Decryption
document.getElementById('input').addEventListener('change', function (e) {
  const file = document.getElementById('input').files[0]
  const file2 = document.getElementById('input').files[1]
  const password = document.getElementById('psw').value
  const blocks = document.getElementById('block').value;
  (
    async () => {
      const seckeyFile = await file.text()
      const block = blocks.split(',')
      const fileContents = document.getElementById('filecontents')
      const keys = await keyfiles.encryption_keyfiles([seckeyFile], password)
      const plaintext = await decryption(file2, keys[0], block)
      fileContents.innerText = plaintext
    })()
})

// KeyGen
const button = document.getElementById('submit')
button.addEventListener('click', async function (event) {
  const seckey = document.getElementById('seckeyfile')
  seckey.innerText = 'hallo'
  const password = await document.getElementById('psw2').value
  const result = keygen.keygen(password)
  const erg = await result
  const pubkey = document.getElementById('pubkeyfile')
  pubkey.innerText = erg[1]
  // const seckey = document.getElementById('seckeyfile')
  // seckey.innerText = erg[0]
})
