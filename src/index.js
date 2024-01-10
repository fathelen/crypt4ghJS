const keygen = require('./keygen')
const keyfiles = require('./check_keyfiles')
const encryption = require('./encryption')
const decryption = require('./decryption')
const reeencryption = require('./reeencryption')
const rearrangment = require('./rearrange')
const checkFileformat = require('./check_fileformat')

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

module.exports = { keygen, keyfiles, encryption, decryption, reeencryption, rearrangment, check_fileformat: checkFileformat }
