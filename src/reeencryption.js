import * as x25519 from '@stablelib/x25519'
import * as enc from './encryption.js'
import * as dec from './decryption.js'
import _sodium from 'libsodium-wrappers'
const PacketTypeEditList = new Uint32Array([1])
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
  const decryptedPackets = await dec.headerDeconstruction(header, keySec)
  if(decryptedPackets[6] && decryptedPackets[6].length > 0){
     try {
      const editlist = decryptedPackets[6]
      const sessionKey = decryptedPackets[0]
      const encryptionMethod = new Uint32Array([0])
      const typeArray = []
      const lenEditUint32 = new Uint32Array([editlist.length])
      const uint8Len = new Uint8Array(lenEditUint32.buffer)
      const type = new Uint8Array(PacketTypeEditList.buffer)
      const editPaket = new Uint8Array(type.length + uint8Len.length + editlist.length)
      editPaket.set(type)
      editPaket.set(uint8Len, type.length)
      editPaket.set(editlist, uint8Len.length + type.length)
      const encPacketDataContent = enc.makePacketDataEnc(encryptionMethod, sessionKey)
      typeArray.push(encPacketDataContent, editPaket)
      const headerPackets = await enc.headerEncrypt(typeArray, newKey.secretKey, keysPub)
      const serializedData = enc.serialize(headerPackets[0], headerPackets[1], headerPackets[2], headerPackets[3])
      return [serializedData, decryptedPackets[4]]
    
  } catch (e) {
    console.trace('Header including edit package could not be computed.')
  }
  } else {
    let serializedData = []
    let sessionKey = decryptedPackets[0]
    try {
        const encryptionMethod = new Uint32Array([0])
        const typeArray = []
        const encPacketDataContent = enc.makePacketDataEnc(encryptionMethod, sessionKey)
        typeArray.push(encPacketDataContent)
        const headerPackets = await enc.headerEncrypt(typeArray, newKey.secretKey, keysPub)
        serializedData = enc.serialize(headerPackets[0], headerPackets[1], headerPackets[2], headerPackets[3])
    } catch (e) {
      console.trace(e)
    } 
    return [serializedData, decryptedPackets[4]]
  }
  


  /*
  if(!decryptedPackets[0][1]){
    const encr = await enc.headerEncrypt(headers, newKey.secretKey, keysPub)
     serializedData = enc.serialize(encr[0], keysPub[0], encr[2], encr[3])
    return [serializedData, headerPackets[2]]
  } else {
    serializedData = await enc.encHeaderEdit(newKey.secretKey, keysPub, decryptedPackets[0][1])
    return [serializedData[0], headerPackets[2]] 
  } */
}

