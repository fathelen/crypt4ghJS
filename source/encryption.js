const helperfunction = require('./helper functions')
const ChaCha20Poly1305 = require('@stablelib/chacha20poly1305')
const x25519 = require('@stablelib/x25519')
const Blake2b = require('@stablelib/blake2b')
const enc = require('./encryption')

const SEGMENT_SIZE = 65536
const PacketTypeDataEnc = new Uint32Array([0])
const PacketTypeEditList = new Uint32Array([1])
const magicBytestring = helperfunction.string2byte('crypt4gh')

/**
 * Main function to encrypt given data in crypt4gh format.
 * @param {*} unencryptedData => unencrypted data that will be encrypted according to crypt4gh
 * @param {*} secretkey => secretkey of the uploading person (32 byte Uint8array)
 * @param {*} publicKeys => List of public keys for all persons, that will be able to decrypt the data (List of 32 byte Uint8arrays)
 * @param {*} blocks => optional parameter, if only certain blocks (64kb) of the data should be encrypted and stored
 * @param {*} editlist => optional parameter, list of bytes which a decrypting person is allowed to decrypt.
 * @returns => Arraylist of encrypted data
 */
exports.encryption = async function * (unencryptedData, secretkey, publicKeys, blocks, editlist) {
  try {
    // header part
    const encryptionMethod = new Uint32Array([0])
    const sessionKey = helperfunction.randomBytes(32)
    const typeArray = []
    const encPacketDataContent = enc.make_packet_data_enc(encryptionMethod, sessionKey)
    typeArray.push(encPacketDataContent)
    const headerPackets = enc.header_encrypt(typeArray, secretkey, publicKeys)
    let serializedData
    // body encryption
    const nonce = helperfunction.randomBytes(12)
    const chacha20poly1305 = new ChaCha20Poly1305.ChaCha20Poly1305(sessionKey)
    if (blocks && !editlist) {
      for await (const val of encryptBlock(headerPackets, blocks, chacha20poly1305, unencryptedData, nonce)) {
        yield await Promise.resolve(val)
      }
    } else if (editlist && !blocks) {
      for await (const val of encryptEditlist(editlist, encryptionMethod, sessionKey, publicKeys, secretkey, unencryptedData, chacha20poly1305, nonce)) {
        yield await Promise.resolve(val)
      }
    } else if (!blocks && !editlist) {
      serializedData = enc.serialize(headerPackets[0], headerPackets[1], headerPackets[2], headerPackets[3])
      const chunksize = SEGMENT_SIZE
      let offset = 0
      while (offset < unencryptedData.length) {
        const chunkfile = await unencryptedData.subarray(offset, offset + chunksize)
        const encChunk = chacha20poly1305.seal(nonce, chunkfile)
        if (offset === 0) {
          const nonceEnc = new Uint8Array(serializedData.length + nonce.length + encChunk.length)
          nonceEnc.set(serializedData)
          nonceEnc.set(nonce, serializedData.length)
          nonceEnc.set(encChunk, nonce.length + serializedData.length)
          offset += chunksize
          yield await Promise.resolve(nonceEnc)
        } else {
          const nonceEnc = new Uint8Array(nonce.length + encChunk.length)
          nonceEnc.set(nonce)
          nonceEnc.set(encChunk, nonce.length)
          offset += chunksize
          yield await Promise.resolve(nonceEnc)
        }
      }
    }
  } catch (e) {
    console.trace('Encryption not possible.')
  }
}

/**
 * Function to create the encryption package
 * @param {*} encryptionMethode => which method is used for encryption (only chacha20poly1305 implemented)
 * @param {*} sessionKey => key to decrypt the input data
 * @returns encryption package as Uint8array
 */
exports.make_packet_data_enc = function (encryptionMethode, sessionKey) {
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
exports.header_encrypt = function (headerContent, seckey, pubkeys) {
  try {
    const nonce = helperfunction.randomBytes(12)
    const k = x25519.generateKeyPairFromSeed(seckey)
    let sharedkey
    const encryptedHeader = []
    const uint8Data = new Uint8Array(PacketTypeDataEnc.buffer)
    let encrMethod
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
        const chacha20poly1305 = new ChaCha20Poly1305.ChaCha20Poly1305(sharedkey)
        const sealedHeader = chacha20poly1305.seal(nonce, headerContent[j])
        tuple.push(sealedHeader)
      }
      encryptedHeader.push(tuple)
    }
    const ke = k.publicKey
    return [encrMethod, ke, nonce, encryptedHeader, sharedkey]
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
exports.serialize = function (methode, wPubkey, nonce, packets) {
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
exports.encryption_edit = async function (editList, encryptionMethod, sessionKey, publicKeys, secretkey) {
  try {
    const typeArray = []
    if (Array.isArray(editList[0]) === true) {
      const editPackets = enc.make_packet_edit_lists(editList)
      const encPacketDataContent = enc.make_packet_data_enc(encryptionMethod, sessionKey)
      if (editPackets.length === publicKeys.length) {
        const headerPackets = enc.header_encrypt_multi_edit(editPackets, encPacketDataContent, secretkey, publicKeys)
        const serializedData = enc.serialize(headerPackets[0], headerPackets[1], headerPackets[2], headerPackets[3])
        return [serializedData, 0]
      }
    } else {
      const editPacket = enc.make_packet_edit_list(editList)
      const encPacketDataContent = enc.make_packet_data_enc(encryptionMethod, sessionKey)
      typeArray.push(encPacketDataContent, editPacket)
      const headerPackets = enc.header_encrypt(typeArray, secretkey, publicKeys)
      const serializedData = enc.serialize(headerPackets[0], headerPackets[1], headerPackets[2], headerPackets[3])
      return [serializedData, 1]
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
exports.make_packet_edit_list = function (editList) {
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
exports.make_packet_edit_lists = function (editList) {
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
exports.header_encrypt_multi_edit = function (editLists, encryptionPaket, seckey, pubkeys) {
  try {
    let headerContent = []
    const nonce = helperfunction.randomBytes(12)
    const k = x25519.generateKeyPairFromSeed(seckey)
    let sharedkey
    const encryptedHeader = []
    const uint8Data = new Uint8Array([0, 0, 0, 0])
    let encrMethod
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
        const chacha20poly1305 = new ChaCha20Poly1305.ChaCha20Poly1305(sharedkey)
        const sealedHeader = chacha20poly1305.seal(nonce, headerContent[j])
        tuple.push(sealedHeader)
      }
      encryptedHeader.push(tuple)
    }
    const ke = k.publicKey
    return [encrMethod, ke, nonce, encryptedHeader]
  } catch (e) {
    console.trace('Header for encryption with mulitple edit lists could not be computed.')
  }
}

/**
 * Function to compute the encrypted body if the parameter block ist given.
 * @param {*} headerPackets => encrypted header packets
 * @param {*} blocks => blocks to encrypt
 * @param {*} chacha20poly1305 => encryption method
 * @param {*} unencryptedData => given data
 * @param {*} nonce => nonce for encryption (12byte)
 * @returns => List of Uint8Arrays containing the crypt4gh encrypted data
 */
async function * encryptBlock (headerPackets, blocks, chacha20poly1305, unencryptedData, nonce) {
  try {
    const serializedData = enc.serialize(headerPackets[0], headerPackets[1], headerPackets[2], headerPackets[3])
    for (let i = 0; i < blocks.length; i++) {
      const offset = (blocks[i] - 1) * SEGMENT_SIZE
      const chunksize = SEGMENT_SIZE
      const chunkfile = await unencryptedData.subarray(offset, offset + chunksize)
      const encChunk = chacha20poly1305.seal(nonce, chunkfile)
      if (i === 0) {
        const nonceEnc = new Uint8Array(nonce.length + encChunk.length + serializedData.length)
        nonceEnc.set(serializedData)
        nonceEnc.set(nonce, serializedData.length)
        nonceEnc.set(encChunk, nonce.length + serializedData.length)
        yield await Promise.resolve(nonceEnc)
      } else {
        const nonceEnc = new Uint8Array(nonce.length + encChunk.length)
        nonceEnc.set(nonce)
        nonceEnc.set(encChunk, nonce.length)
        yield await Promise.resolve(nonceEnc)
      }
    }
  } catch (e) {
    console.trace('Encryption with Blocks was not possible.')
  }
}

/**
 * Function to compute the encrypted body, if an edit list/s is given.
 * @param {*} editlist => list of bytes that the reader should be able to decrypt.
 * @param {*} encryptionMethod => only chacha20poly1305 implemented
 * @param {*} sessionKey => key for encryption
 * @param {*} publicKeys => list of public keys
 * @param {*} secretkey => uploader's secret key
 * @param {*} unencryptedData => given data
 * @param {*} chacha20poly1305 => encryption method
 * @param {*} nonce => => nonce for encryption (12byte)
 * @returns => List of Uint8Arrays containing the crypt4gh encrypted data
 */
async function * encryptEditlist (editlist, encryptionMethod, sessionKey, publicKeys, secretkey, unencryptedData, chacha20poly1305, nonce) {
  try {
    console.log(editlist)
    const serializedData = await enc.encryption_edit(editlist, encryptionMethod, sessionKey, publicKeys, secretkey)
    const chunksize = SEGMENT_SIZE
    let offset = 0
    while (offset < unencryptedData.length) {
      if (offset === 0) {
        const chunkfile = await unencryptedData.subarray(offset, offset + chunksize)
        const encChunk = chacha20poly1305.seal(nonce, chunkfile)
        const nonceEnc = new Uint8Array(nonce.length + encChunk.length + serializedData[0].length)
        nonceEnc.set(serializedData[0])
        nonceEnc.set(nonce, serializedData[0].length)
        nonceEnc.set(encChunk, nonce.length + serializedData[0].length)
        offset += chunksize
        yield await Promise.resolve(nonceEnc)
      } else {
        const chunkfile = await unencryptedData.subarray(offset, offset + chunksize)
        const encChunk = chacha20poly1305.seal(nonce, chunkfile)
        const nonceEnc = new Uint8Array(nonce.length + encChunk.length)
        nonceEnc.set(nonce)
        nonceEnc.set(encChunk, nonce.length)
        offset += chunksize
        yield await Promise.resolve(nonceEnc)
      }
    }
  } catch (e) {
    console.trace('Encryption with Editlist was not possible.')
  }
}
