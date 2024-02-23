import * as helperfunction from './helper functions.js'
import * as x25519 from '@stablelib/x25519'
import * as Blake2b from '@stablelib/blake2b'
import _sodium from 'libsodium-wrappers'
import { Buffer } from 'buffer'
/*
const helperfunction = require('./helper functions')
const x25519 = require('@stablelib/x25519')
const Blake2b = require('@stablelib/blake2b')
const enc = require('./encryption')
const _sodium = require('libsodium-wrappers') */
// const Buffer = require('buffer/').Buffer
// const chacha20poly1305 = require('@noble/ciphers/chacha')
// const utf8ToBytes = require('@noble/ciphers/utils')
// const randomBytes = require('@noble/ciphers/webcrypto')

const PacketTypeDataEnc = new Uint32Array([0])
const PacketTypeEditList = new Uint32Array([1])
const magicBytestring = helperfunction.string2byte('crypt4gh')

export async function encryption (headerInfo, text, counter, blocks) {
  let encText = new Uint8Array()
  if (blocks && blocks.includes(counter)) {
    encText = await pureEncryption(text, headerInfo[1])
    return encText
  } else if (!blocks) {
    encText = await pureEncryption(text, headerInfo[1])
    return encText
  }
}

export async function encHead (seckey, pubkey, edit) {
  let header = new Uint8Array()
  if (edit) {
    header = await encHeaderEdit(seckey, pubkey, edit)
  } else {
    header = await encHeader(seckey, pubkey)
  }
  return header
}

export async function encHeader (secretkey, publicKeys) {
  let serializedData = []
  let sessionKey = new Uint8Array(32)
  try {
    await (async () => {
      await _sodium.ready
      const sodium = _sodium
      const encryptionMethod = new Uint32Array([0])
      sessionKey = sodium.randombytes_buf(32)
      const typeArray = []
      const encPacketDataContent = makePacketDataEnc(encryptionMethod, sessionKey)
      typeArray.push(encPacketDataContent)
      const headerPackets = await headerEncrypt(typeArray, secretkey, publicKeys)
      serializedData = serialize(headerPackets[0], headerPackets[1], headerPackets[2], headerPackets[3])
    })()
  } catch (e) {
    console.trace(e)
    // console.trace('Header Encryption not possible.')
  }

  return [serializedData, sessionKey]
}

export async function encHeaderEdit (secretkey, publicKeys, editlist) {
  try {
    let serializedData = new Uint8Array()
    let sessionKey = new Uint8Array()
    // header part
    await (async () => {
      await _sodium.ready
      const sodium = _sodium
      const encryptionMethod = new Uint32Array([0])
      sessionKey = sodium.randombytes_buf(32)
      serializedData = await encryptionEdit(editlist, encryptionMethod, sessionKey, publicKeys, secretkey)
    })()
    return [serializedData, sessionKey]
  } catch (e) {
    console.trace('Header Encryption not possible.')
  }
}

export async function pureEncryption (chunk, key) {
  /*
  const nonce = _sodium.randombytes_buf(12) // randomBytes.randomBytes(12)
  const chacha = chacha20poly1305.chacha20poly1305(key, nonce)
  // const data = utf8ToBytes.utf8ToBytes(chunk)
  const ciphertext = chacha.encrypt(chunk)
  return ciphertext */
  let x = new Uint8Array()
  await (async () => {
    await _sodium.ready
    const sodium = _sodium
    const initVector = sodium.randombytes_buf(12)
    const decData = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(chunk, null, null, initVector, key)
    const decNonce = Buffer.concat([initVector, decData])
    x = new Uint8Array(decNonce)
  })()
  return x
}

/**
 * Function to create the encryption package
 * @param {*} encryptionMethode => which method is used for encryption (only chacha20poly1305 implemented)
 * @param {*} sessionKey => key to decrypt the input data
 * @returns encryption package as Uint8array
 */
function makePacketDataEnc (encryptionMethode, sessionKey) {
  try {
    const uint8EncMethod = new Uint8Array(encryptionMethode.buffer)
    const uint8TypeData = new Uint8Array(PacketTypeDataEnc.buffer)
    const encPacketDataUint8 = new Uint8Array(uint8EncMethod.length + uint8TypeData.length + sessionKey.length)
    encPacketDataUint8.set(uint8TypeData)
    encPacketDataUint8.set(uint8EncMethod, uint8TypeData.length)
    encPacketDataUint8.set(sessionKey, uint8EncMethod.length + uint8TypeData.length)
    return encPacketDataUint8
  } catch (e) {
    console.trace('header encryption package could not be computed.')
  }
}

/**
 * Function to compute encrypted headerpackages
 * @param {*} headerContent => List of encrypted data package and if there edit package
 * @param {*} seckey => seckret the of the uploading person
 * @param {*} pubkeys => List of public keys of the persons getting access to the data
 * @returns => List of encryption method, public key of the uploading person, nonce, encrypted headerpackages and sharedkey for decryption
 */
export async function headerEncrypt (headerContent, seckey, pubkeys) {
  try {
    let encrMethod
    let ke
    let initVector
    let sharedkey
    const encryptedHeader = []
    await (async () => {
      await _sodium.ready
      const sodium = _sodium
      initVector = sodium.randombytes_buf(12)
      const k = x25519.generateKeyPairFromSeed(seckey)
      const uint8Data = new Uint8Array(PacketTypeDataEnc.buffer)
      let d = 0
      for (let i = 0; i < pubkeys.length; i++) {
        const tuple = []
        for (let j = 0; j < headerContent.length; j++) {
          if (helperfunction.equal(headerContent[j].subarray(0, 4), uint8Data) === true && d === 0) {
            encrMethod = [headerContent[j][4], headerContent[j][5], headerContent[j][6], headerContent[j][7]].join('')
            d++
          }
          const dh = x25519.sharedKey(seckey, pubkeys[i])
          const uint8Blake2b = new Uint8Array(dh.length + pubkeys[0].length + pubkeys[i].length)
          uint8Blake2b.set(dh)
          uint8Blake2b.set(pubkeys[i], dh.length)
          uint8Blake2b.set(k.publicKey, dh.length + pubkeys[i].length)
          const blake2b = new Blake2b.BLAKE2b()
          blake2b.update(uint8Blake2b)
          const uint8FromBlake2b = blake2b.digest()
          sharedkey = uint8FromBlake2b.subarray(0, 32)
          const decData = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(headerContent[j], null, null, initVector, sharedkey)
          tuple.push(decData)
        }
        encryptedHeader.push(tuple)
      }
      ke = k.publicKey
    })()
    return [encrMethod, ke, initVector, encryptedHeader, sharedkey]
  } catch (e) {
    console.trace('header could not be encrypted.')
  }
}

/**
 * Function to complete the header according to crypt4gh format
 * @param {*} methode => encryption method (only chacha20poly1305)
 * @param {*} wPubkey => public key of the uploading person
 * @param {*} nonce => nonce used for encryption
 * @param {*} packets => List of encrypted header packages
 * @returns => Uint8array containing the complete crypt4gh format header
 */
export function serialize (methode, wPubkey, nonce, packets) {
  try {
    if (Array.isArray(packets[0])) {
      packets = [].concat(...packets)
    }
    // erstellen des äußersten headerteils -- magicbytestring, version, packetcount
    const packetCountUint32 = new Uint32Array([packets.length])
    const packetCountBuffer = packetCountUint32.buffer
    const uint8PacketCount = new Uint8Array(packetCountBuffer)
    const versionUint32 = new Uint32Array([1])
    const versionBuffer = versionUint32.buffer
    const uint8Version = new Uint8Array(versionBuffer)
    const headerArray = new Uint8Array(uint8PacketCount.length + uint8Version.length + magicBytestring.length)
    headerArray.set(magicBytestring)
    headerArray.set(uint8Version, magicBytestring.length)
    headerArray.set(uint8PacketCount, magicBytestring.length + uint8Version.length)
    // erstellen des inneren header teils -- packet länge, encmethode, wpubkey,nonce,encdata,mac
    let packetLength = 0
    const allPackets = []
    for (let i = 0; i < packets.length; i++) {
      const packetL = new Uint32Array([packets[i].length + methode.length + wPubkey.length + nonce.length + 4])
      const packetLBuffer = packetL.buffer
      const packetLUint8 = new Uint8Array(packetLBuffer)
      const packetUint8 = new Uint8Array(packetLUint8.length + methode.length + wPubkey.length + packets[i].length + nonce.length)
      packetUint8.set(packetLUint8)
      packetUint8.set(methode, packetLUint8.length)
      packetUint8.set(wPubkey, packetLUint8.length + methode.length)
      packetUint8.set(nonce, packetLUint8.length + methode.length + wPubkey.length)
      packetUint8.set(packets[i], packetLUint8.length + methode.length + wPubkey.length + nonce.length)
      allPackets.push(packetUint8)
      packetLength = packetLength + packetUint8.length
    }
    // header bestandteile zusammenfügen
    let position = headerArray.length
    const completeHeader = new Uint8Array(headerArray.length + packetLength)
    completeHeader.set(headerArray)
    for (let i = 0; i < allPackets.length; i++) {
      completeHeader.set(allPackets[i], position)
      position = position + allPackets[i].length
    }
    return completeHeader
  } catch (e) {
    console.trace('Encrypted header could not be completed.')
  }
}

/**
 * Function to compute the complete header if an edit list or multiple edit lists are given
 * @param {*} editList => one or two dimensional array depends on whether one ore more edit lists are given
 * @param {*} encryptionMethod => encryption method (only chacha20poly1305)
 * @param {*} sessionKey => key used to encrypt the input data
 * @param {*} publicKeys => List of public keys of the persons getting access to the data
 * @param {*} secretkey => secret key of the uploading person
 * @param {*} type_array => contains the encryption package and the edit package
 * @returns => Uint8array containing the complete crypt4gh format header
 */
export async function encryptionEdit (editList, encryptionMethod, sessionKey, publicKeys, secretkey) {
  try {
    const typeArray = []
    if (Array.isArray(editList[0]) === true) {
      const editPackets = makePacketEditLists(editList)
      const encPacketDataContent = makePacketDataEnc(encryptionMethod, sessionKey)
      if (editPackets.length === publicKeys.length) {
        const headerPackets = await headerEncryptMultiEdit(editPackets, encPacketDataContent, secretkey, publicKeys)
        const serializedData = serialize(headerPackets[0], headerPackets[1], headerPackets[2], headerPackets[3])
        return serializedData
      }
    } else {
      const editPacket = makePacketEditList(editList)
      const encPacketDataContent = makePacketDataEnc(encryptionMethod, sessionKey)
      typeArray.push(encPacketDataContent, editPacket)
      const headerPackets = await headerEncrypt(typeArray, secretkey, publicKeys)
      const serializedData = serialize(headerPackets[0], headerPackets[1], headerPackets[2], headerPackets[3])
      return serializedData
    }
  } catch (e) {
    console.trace('Header including edit package could not be computed.')
  }
}

/**
 * Function to compute the edit list package
 * @param {*} editList  => given edit list
 * @returns edit package (Uint8array)
 */
export function makePacketEditList (editList) {
  try {
    const bigEdits = []
    for (let i = 0; i < editList.length; i++) {
      bigEdits.push(BigInt(editList[i]))
    }
    const editUint64 = new BigUint64Array(bigEdits)
    const editUint8 = new Uint8Array(editUint64.buffer)
    const lenEditUint32 = new Uint32Array([editList.length])
    const uint8Len = new Uint8Array(lenEditUint32.buffer)
    const type = new Uint8Array(PacketTypeEditList.buffer)
    const uint8Complete = new Uint8Array(type.length + uint8Len.length + editUint8.length)
    uint8Complete.set(type)
    uint8Complete.set(uint8Len, type.length)
    uint8Complete.set(editUint8, uint8Len.length + type.length)
    return uint8Complete
  } catch (e) {
    console.trace('edit list package could not be computed.')
  }
}

/**
 * Function to compute edit packages if multiple edit lists are given
 * @param {*} editList => two dimensional array containing all given edit lists
 * @returns => edit packages (Array of Uint8arrays)
 */
export function makePacketEditLists (editList) {
  try {
    const allEdits = []
    for (let i = 0; i < editList.length; i++) {
      const bigEdits = []
      for (let j = 0; j < editList[i].length; j++) {
        bigEdits.push(BigInt(editList[i][j]))
      }
      const editUint64 = new BigUint64Array(bigEdits)
      const editUint8 = new Uint8Array(editUint64.buffer)
      const lenEditUint32 = new Uint32Array([editList[i].length])
      const uint8Len = new Uint8Array(lenEditUint32.buffer)
      const type = new Uint8Array(PacketTypeEditList.buffer)
      const uint8Complete = new Uint8Array(type.length + uint8Len.length + editUint8.length)
      uint8Complete.set(type)
      uint8Complete.set(uint8Len, type.length)
      uint8Complete.set(editUint8, uint8Len.length + type.length)
      allEdits.push(uint8Complete)
    }
    return allEdits
  } catch (e) {
    console.trace('List of edit list packages could not be computed.')
  }
}

/**
 * Function to encrypt the header packages if multiple edit lists are given
 * @param {*} editLists => Array of Uint8arrays containing the edit lists
 * @param {*} encryptionPaket => completed encryption package
 * @param {*} seckey => secret key of the uploading person
 * @param {*} pubkeys => List of public keys of the persons getting access to the data
 * @returns  List of encryption method, public key of the uploading person, nonce, encrypted headerpackages and sharedkey for decryption
 */
export async function headerEncryptMultiEdit (editLists, encryptionPaket, seckey, pubkeys) {
  try {
    let headerContent = []
    let x = new Uint8Array()
    let initVector = new Uint8Array()
    let encrMethod = new Uint8Array()
    const encryptedHeader = []
    let ke = new Uint8Array()
    await (async () => {
      await _sodium.ready
      const sodium = _sodium
      initVector = sodium.randombytes_buf(12)
      const k = x25519.generateKeyPairFromSeed(seckey)
      let sharedkey
      const uint8Data = new Uint8Array([0, 0, 0, 0])
      for (let i = 0; i < pubkeys.length; i++) {
        headerContent = [encryptionPaket, editLists[i]]
        const tuple = []
        for (let j = 0; j < headerContent.length; j++) {
          if (helperfunction.equal(headerContent[j].subarray(0, 4), uint8Data) === true) {
            encrMethod = new Uint8Array([headerContent[0][4], headerContent[0][5], headerContent[0][6], headerContent[0][7]])
          }
          const dh = x25519.sharedKey(seckey, pubkeys[i])
          const uint8Blake2b = new Uint8Array(dh.length + k.publicKey.length + pubkeys[i].length)
          uint8Blake2b.set(dh)
          uint8Blake2b.set(pubkeys[i], dh.length)
          uint8Blake2b.set(k.publicKey, dh.length + pubkeys[i].length)
          const blake2b = new Blake2b.BLAKE2b()
          blake2b.update(uint8Blake2b)
          const uint8FromBlake2b = blake2b.digest()
          sharedkey = uint8FromBlake2b.subarray(0, 32)
          const decData = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(headerContent[j], null, null, initVector, sharedkey)
          // const decNonce = Buffer.concat([initVector, decData])
          x = new Uint8Array(decData)
          tuple.push(x)
        }
        encryptedHeader.push(tuple)
      }
      ke = k.publicKey
    })()
    return [encrMethod, ke, initVector, encryptedHeader]
  } catch (e) {
    console.trace('Header for encryption with mulitple edit lists could not be computed.')
  }
}

export default { encryption, encHead, encHeader, encHeaderEdit, pureEncryption, headerEncrypt, serialize, encryptionEdit, makePacketEditList, makePacketEditLists, headerEncryptMultiEdit }
