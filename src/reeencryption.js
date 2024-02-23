import * as x25519 from '@stablelib/x25519'
import * as enc from './encryption.js'
import * as dec from './decryption.js'
/*
const x25519 = require('@stablelib/x25519')
const enc = require('./encryption')
const dec = require('./decryption') */

const SEGMENTSIZE = 65536
const newKey = x25519.generateKeyPair()

/**
 * Function to reencrypt an already crypt4gh encrypted file. (change header to make it accessable for other persons)
 * @param {*} encryptedData => crypt4gh file content (Uint8array)
 * @param {*} keysPub => List of public keys (Array of Uint8arrays)
 * @param {*} keySec => uploaders secret key (Uint8array)
 * @returns => Array of Uint8arrays containing new crypt4gh file
 */
export async function * reencrypt (encryptedData, keysPub, keySec) {
  try {
    // Decrypt and Reencrypt header of infile
    const header = await encryptedData.subarray(0, 10000)
    const headerPackets = dec.parse(header)
    const decryptedPackets = dec.decryptHeader(headerPackets[0], keySec)
    const headers = [decryptedPackets[0][0]]
    headers.push(decryptedPackets[0][0])
    keysPub.unshift(newKey.publicKey)
    const encr = enc.headerEncrypt(headers, newKey.secretKey, keysPub)
    const serializedData = enc.serialize(encr[0], keysPub[0], encr[2], encr[3])
    const chunksize = SEGMENTSIZE
    let offset = headerPackets[2]
    while (offset < encryptedData.length) {
      if (offset === 0) {
        const chunkfile = await encryptedData.subarray(offset, offset + chunksize)
        const nonceEnc = new Uint8Array(serializedData.length + chunkfile.length)
        nonceEnc.set(serializedData)
        nonceEnc.set(chunkfile, serializedData.length)
        yield await Promise.resolve(nonceEnc)
        offset += chunksize
      } else {
        const chunkfile = await encryptedData.subarray(offset, offset + chunksize)
        yield await Promise.resolve(chunkfile)
        offset += chunksize
      }
    }
  } catch (e) {
    console.trace('Reeencryption not possible.')
  }
}

export async function streamReencryptHeader (header, keysPub, keySec) {
  const headerPackets = dec.parse(header)
  const decryptedPackets = await dec.decryptHeader(headerPackets[0], keySec)
  const headers = [decryptedPackets[0][0]]
  headers.push(decryptedPackets[0][0])
  keysPub.unshift(newKey.publicKey)
  const encr = await enc.headerEncrypt(headers, newKey.secretKey, keysPub)
  const serializedData = enc.serialize(encr[0], keysPub[0], encr[2], encr[3])
  return [serializedData, headerPackets[2]]
}

