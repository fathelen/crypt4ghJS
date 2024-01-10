const keygen = require('./keygen')
const keyfiles = require('./check_keyfiles')
const encryption = require('./encryption')
const decryption = require('./decryption')
const reeencryption = require('./reeencryption')
const rearrangment = require('./rearrange')
const checkFileformat = require('./check_fileformat')

module.exports = { keygen, keyfiles, encryption, decryption, reeencryption, rearrangment, check_fileformat: checkFileformat }
