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
