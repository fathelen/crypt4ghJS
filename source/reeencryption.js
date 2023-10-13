const x25519 = require('@stablelib/x25519')
const enc = require('./encryption')
const dec = require('./decryption')

const SEGMENTSIZE = 65536
const newKey = x25519.generateKeyPair()

/**
 * Function to reencrypt an already crypt4gh encrypted file. (change header to make it accessable for other persons)
 * @param {*} encryptedData => crypt4gh file content (Uint8array)
 * @param {*} keysPub => List of public keys (Array of Uint8arrays)
 * @param {*} keySec => uploaders secret key (Uint8array)
 * @returns => Array of Uint8arrays containing new crypt4gh file
 */
exports.reencrypt = async function (encryptedData, keysPub, keySec) {
  try {
    // Decrypt and Reencrypt header of infile
    const fullEnc = []
    const header = await encryptedData.subarray(0, 10000)
    const headerPackets = dec.parse(header)
    const decryptedPackets = dec.decrypt_header(headerPackets[0], keySec)
    const headers = [decryptedPackets[0][0]]
    headers.push(decryptedPackets[0][0])
    keysPub.unshift(newKey.publicKey)
    const encr = enc.header_encrypt(headers, newKey.secretKey, keysPub)
    const serializedData = enc.serialize(encr[0], keysPub[0], encr[2], encr[3])
    fullEnc.push(serializedData)
    const chunksize = SEGMENTSIZE
    let offset = headerPackets[2]
    while (offset < encryptedData.length) {
      const chunkfile = await encryptedData.subarray(offset, offset + chunksize)
      // Blob.arrayBuffer() can be polyfilled with a FileReader
      fullEnc.push(chunkfile)
      offset += chunksize
    }
    return fullEnc
  } catch (e) {
    console.trace('Reeencryption not possible.')
  }
}
