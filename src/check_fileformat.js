import * as dec from './decryption.js'

// const dec = require('./decryption')

/**
 * Function to check whether an already encrypted file is in crypt4gh format or not
 * and whether the person uploading the file, has access to the unencrypted data
 * @param {*} input => data to check for crypt4gh format
 * @param {*} seckey => key to decrypt input
 * @returns => false, if data can't be decrypted. true, if it can be decrypted.
 */
export async function check (input, seckey) {
  try {
    const header = await input.subarray(0, 1000)
    const headerPackets = dec.parse(header)
    const decryptedPackets = await dec.decryptHeader(headerPackets[0], seckey)
    if (decryptedPackets[0].length === 0) {
      return false
    } else {
      return true
    }
  } catch (e) {
    console.trace("File checking wasn't possible!")
  }
}

export default check
