const helperfunction = require('./helper functions')
const ChaCha20Poly1305 = require('@stablelib/chacha20poly1305')
const x25519 = require('@stablelib/x25519')
const Blake2b = require('@stablelib/blake2b')
const dec = require('./decryption')

exports.SEGMENT_SIZE = 65536
const fullSegment = 65564
const PacketTypeDataEnc = '0000'
const PacketTypeEditList = '1000'
const encryptionMethod = '0000' // only (xchacha20poly1305)
const magicBytestring = helperfunction.string2byte('crypt4gh')

/**
 * Main decryption function
 * @param {*} encryptedData => crypt4gh encrypted data in Uint8Array format
 * @param {*} seckey => Seckey as Uint8Array of 32bytes
 * @param {*} blocks => optional Parameter, if only defined blocks of size 64kb
 *                      should be ecrypted
 * @returns => decrypted data in an ArrayList, each value is a 64kb block of the
 *             data
 */
exports.decryption = async function * (encryptedData, seckey, blocks = []) {
  const header = await encryptedData.subarray(0, 1000)
  const headerInformation = dec.header_deconstruction(header, seckey)
  const chacha20poly1305 = new ChaCha20Poly1305.ChaCha20Poly1305(headerInformation[0])
  try {
    if (blocks && !headerInformation[3].length > 0) {
      for await (const val of decryptionBlocks(encryptedData, blocks, headerInformation, chacha20poly1305)) {
        yield await Promise.resolve(val[0])
      }
    } else if (headerInformation[3].length > 0 && blocks == null) {
      for await (const val of decryptEdit(headerInformation, encryptedData, chacha20poly1305)) {
        yield await Promise.resolve(val)
      }
    } else if (headerInformation[3].length > 0 && blocks != null) {
      console.trace('Combination of blocks and edit list is not possible')
    } else {
      for (let i = headerInformation[4]; i < encryptedData.length; i = i + 65564) {
        const nonce = await encryptedData.subarray(i, i + 12)
        const enc = await encryptedData.subarray(i + 12, i + 12 + dec.SEGMENT_SIZE + 16)
        const plaintext = chacha20poly1305.open(nonce, enc)
        yield await Promise.resolve(plaintext)
      }
    }
  } catch (e) {
    console.trace('Decryption was not possible')
  }
}

exports.pureDecryption = async function (d, key) {
  const chacha20poly1305 = new ChaCha20Poly1305.ChaCha20Poly1305(key)
  const nonce = await d.subarray(0, 12)
  const enc = await d.subarray(12)
  const plaintext = chacha20poly1305.open(nonce, enc)
  return await Promise.resolve(plaintext)
}

exports.pureEdit = function (d) {
  const edits = calculateEditlist(d)
  return edits
}
/**
 * Function checks if a decryption is possible, by checking if the given seckey is able to decode a header packet.
 * @param {*} header => header part of the encrypted data
 * @param {*} seckeys => secret key to decrypt header packet
 * @returns => List containing the sessionkey, nonce, body, editlist and position bodystart
 */
exports.header_deconstruction = function (header, seckeys) {
  try {
    const headerPackets = dec.parse(header)
    const decryptedPackets = dec.decrypt_header(headerPackets[0], seckeys)
    const partitionedPackages = partitionPackets(decryptedPackets[0])
    const sessionKey = parseEncPacket(partitionedPackages[0][0])
    return [sessionKey, decryptedPackets[2], headerPackets[1], partitionedPackages[1], headerPackets[2]]
  } catch (e) {
    console.trace('header deconstruction not possible.')
  }
}

/**
 * Function to check if the input data is in Crypt4gh format, version number and #packages
 * @param {*} header => start of the file containing the header packages
 * @returns => List containing the list of header packages, body and position bodystart
 */
exports.parse = function (header) {
  try {
    // checken magic number
    const magicHeaderDecryption = new TextDecoder().decode(header.subarray(0, 8))
    const magicHeaderOrignal = new TextDecoder().decode(magicBytestring)
    if (magicHeaderDecryption !== magicHeaderOrignal) console.trace('Not a crypt4gh file')
    // check version number
    const version = new Uint8Array(header.subarray(8, 12))
    if (version[0] !== 1) console.trace('Only version 1 is accepted')
    // check packet count
    const numPakets = new Uint32Array(new Uint8Array(header.subarray(12, 16)))
    if (numPakets[0] === 0) console.trace('No packages!')
    // extract packets -- returns list of packets
    const extracted = dec.extract_packets(numPakets[0], header)
    return [extracted[0], extracted[1], extracted[2]]
  } catch (e) {
    console.trace('header parsing not possible.')
  }
}

/**
 * Function to extract the individual header packages from the header
 * @param {*} packetNum => #header packages
 * @param {*} header => start of the file containing the header packages
 * @returns  => List containing the list of header packages, body and position bodystart
 */
exports.extract_packets = function (packetNum, header) {
  const listHeaderPackages = []
  let position = 0
  try {
    for (let i = 0; i < packetNum; i++) {
      const currentPackage = []
      const headerStart = 16
      if (i === 0) {
        const firstUint32 = new Uint32Array(new Uint8Array(header.slice(16, 20).buffer))
        position = headerStart // first_header_packet_length + header_start;
        for (let j = 0; j < firstUint32[0]; j++) {
          currentPackage.push(header[position + j])
        }
        position = position + firstUint32[0]
      } else {
        const uint32 = new Uint32Array(new Uint8Array(header.slice(position, position + 4)))
        for (let j = 0; j < uint32[0]; j++) {
          currentPackage.push(header[position + j])
        }
        position = position + uint32[0]
      }
      listHeaderPackages.push(currentPackage)
    }
    const bodyBuffer = header.slice(position)
    return [listHeaderPackages, bodyBuffer, position]
  } catch (e) {
    console.trace("packages couln't be extracted.")
  }
}

/**
 * Function to decrypt the seckey fitting header package
 * @param {*} headerPackets => list of header packages
 * @param {*} seckeys => seckey to decode a header package
 * @returns => List containing the decrypted package, the undecrypted packages and the nonce
 */
exports.decrypt_header = function (headerPackets, seckeys) {
  try {
    seckeys = [seckeys]
    const decryptedPackets = []
    const undecryptablePackets = []
    let nonceUint8
    for (let i = 0; i < headerPackets.length; i++) {
      const wKeyUint8 = new Uint8Array(headerPackets[i].slice(8, 40))
      nonceUint8 = new Uint8Array(headerPackets[i].slice(40, 52))
      const encryptedUint8 = new Uint8Array(headerPackets[i].slice(52))
      for (let j = 0; j < seckeys.length; j++) {
        const k = x25519.generateKeyPairFromSeed(seckeys[j])
        const dh = x25519.sharedKey(seckeys[j], wKeyUint8)
        const uint8Blake2b = new Uint8Array(dh.length + wKeyUint8.length + k.publicKey.length)
        uint8Blake2b.set(dh)
        uint8Blake2b.set(k.publicKey, dh.length)
        uint8Blake2b.set(wKeyUint8, dh.length + wKeyUint8.length)
        const blake2b = new Blake2b.BLAKE2b()
        blake2b.update(uint8Blake2b)
        const uint8FromBlake2b = blake2b.digest()
        const sharedKey = uint8FromBlake2b.subarray(0, 32)
        const chacha20poly1305 = new ChaCha20Poly1305.ChaCha20Poly1305(sharedKey)
        const plaintext = chacha20poly1305.open(nonceUint8, encryptedUint8)
        if (plaintext) {
          decryptedPackets.push(plaintext)
        } else {
          undecryptablePackets.push(headerPackets[i])
        }
      }
    }
    return [decryptedPackets, undecryptablePackets, nonceUint8]
  } catch (e) {
    console.trace('Header could not be decrypted.')
  }
}

/**
 * Function to devide the packages in encryption packages and edit packages
 * @param {*} packets => List of packages
 * @returns => Two dimensional Array containing first the encryption packages and second the edit packages
 */
function partitionPackets (packets) {
  try {
    const encPackets = []
    const editPackets = []
    for (let i = 0; i < packets.length; i++) {
      const packetType = [packets[i][0], packets[i][1], packets[i][2], packets[i][3]].join('')
      if (packetType === PacketTypeDataEnc) {
        encPackets.push(packets[i].subarray(4))
      } else if (packetType === PacketTypeEditList) {
        editPackets.push(packets[i].subarray(8))
      } else console.trace('Invalid package type')
    }
    return [encPackets, editPackets]
  } catch (e) {
    console.trace('Package partition not possible.')
  }
}

/**
 * Function to parse the encryption packages
 * @param {*} packet => encryption package
 * @returns => session key, to decrypt the encrypted data
 */
function parseEncPacket (packet) {
  try {
    const encMethod = [packet[0], packet[1], packet[2], packet[3]].join('')
    let sessionKey
    if (encMethod !== encryptionMethod) console.trace('Invalid encryption method!')
    else {
      sessionKey = packet.slice(4)
    }
    return sessionKey
  } catch (e) {
    console.trace('encryption package could not be parsed.')
  }
}

/**
 * Function to apply the edit list (original algorithm at http://samtools.github.io/hts-specs/crypt4gh.pdf page 15)
 * @param {*} edlist => editlist extracted from the edit package
 * @param {*} decryptedText => already decrypted input data
 * @returns => decrypted data edited according to the editlist
 */
exports.applyEditlist = function (edlist, decryptedText) {
  try {
    const editedData = []
    let pos = BigInt(0)
    const len = BigInt(decryptedText.length)
    for (let i = 0; i < edlist.length; i = i + 2) {
      const discard = edlist[i]
      pos = pos + discard
      if (i === edlist.length - 1) {
        const part = decryptedText.subarray(Number(pos), Number(len))
        editedData.push(part)
      } else {
        const keep = edlist[i + 1]
        const part = decryptedText.subarray(Number(pos), Number(pos) + Number(keep))
        editedData.push(part)
        pos = pos + keep
      }
    }
    let length = 0
    editedData.forEach(item => {
      length += item.length
    })
    // Create a new array with total length and merge all source arrays.
    const mergedArray = new Uint8Array(length)
    let offset = 0
    editedData.forEach(item => {
      mergedArray.set(item, offset)
      offset += item.length
    })
    return mergedArray
  } catch (e) {
    console.trace('edit list could not be applied.')
  }
}

/**
 * Function to decrypt data with blocks parameter
 * @param {*} encryptedData => crypt4gh encrypted data in Uint8Array format
 * @param {*} blocks => List of 64k data blocks that should be decrypted
 * @param {*} headerInformation => Information contained in decrypted header package
 * @param {*} chacha20poly1305 => encryption method
 * @returns => decrypted data
 */
async function * decryptionBlocks (encryptedData, blocks, headerInformation, chacha20poly1305) {
  try {
    for (let i = 0; i < blocks.length; i++) {
      const nonce = await encryptedData.subarray((blocks[i] - 1) * fullSegment + headerInformation[4], (blocks[i] - 1) * fullSegment + headerInformation[4] + 12)
      const enc = await encryptedData.subarray((blocks[i] - 1) * fullSegment + headerInformation[4] + 12, (blocks[i] - 1) * fullSegment + headerInformation[4] + 12 + dec.SEGMENT_SIZE + 16)
      const plaintext = chacha20poly1305.open(nonce, enc)
      yield await Promise.resolve([plaintext, i, blocks[i]])
    }
  } catch (e) {
    console.trace('Decryption with blocks not possible.')
  }
}

/**
 * blocks2encrypt is needed to prepare the edit informations to calculate new editlists for each block
 * @param {*} headerInformation 2 dim array containing the header Informations, needed to decrypt the data
 * @returns an Array containing the addeded editlist (summed values of editlist), the editlist and a boolean if the og editlist was even or odd.
 */
function blocks2encrypt (headerInformation) {
  // 1.Step: Welche Blöcke müssen entschlüsselt werden
  const edit64 = new BigInt64Array(headerInformation[3][0].buffer)
  let editlist = edit64.subarray(1)
  let addedEdit = []
  let j = 0n
  for (let i = 0; i < editlist.length; i++) {
    j = j + editlist[i]
    addedEdit.push(j)
  }
  // ungerade editlist anpassen
  let unEven = false
  const editOdd = new BigInt64Array(editlist.length + 1)
  if (editlist.length % 2 !== 0) {
    unEven = true
    const sum = (editlist.reduce((partialSum, a) => partialSum + a, 0n))
    editOdd.set(editlist)
    editOdd[editOdd.length - 1] = 65536n * ((sum / 65536n) + 1n) - sum
  }
  // 2.Map erstellen
  if (editlist.length % 2 !== 0) {
    addedEdit = []
    editlist = editOdd
    let j = 0n
    for (let i = 0; i < editlist.length; i++) {
      j = j + editlist[i]
      addedEdit.push(j)
    }
  }
  return [addedEdit, editlist, unEven]
}

/**
 * calculateEditlist is a function to calculate edit lists for each block from the original editlist.
 * @param {*} headerInformation 2 dim array containing the header Informations, needed to decrypt the data
 * @param {*} encryptedData encrypted data whitch is about to be decrypted
 * @param {*} chacha20poly1305 decryption method
 * @returns Array containing a map with the edits for each block and a boolean if the og editlist was even or odd.
 */
function calculateEditlist (headerInformation) {
  const preEdit = blocks2encrypt(headerInformation)
  let bEven = 0
  const blocks = new Map()
  for (let i = 0; i < preEdit[0].length; i++) {
    if (i % 2 === 0) {
      bEven = Number(((preEdit[0][i] - 1n) / 65536n) + 1n)
    } else {
      const bOdd = Number(((preEdit[0][i] - 1n) / 65536n) + 1n)
      if (bEven === bOdd && i >= 2) {
        if (Number(((preEdit[0][i - 2] - 1n) / 65536n) + 1n) === bOdd) {
          blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i - 1]])
          blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i]])
        } else {
          const lastKey = [...blocks.keys()].pop()
          const sum = 65536n - ((blocks.get(lastKey).reduce((partialSum, a) => partialSum + a, 0n))) + BigInt((65536 * (bOdd - 2)))
          blocks.set(bEven, [preEdit[1][i - 1] - sum])
          blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i]])
        }
      } else if (bEven === bOdd && i < 2) {
        if (blocks.has(bEven)) {
          if (preEdit[1][i - 1] > 65536n) {
            blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i - 1] - (BigInt(bEven - 1) * 65536n)])
          } else {
            blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i - 1]])
          }
        } else {
          if (preEdit[1][i - 1] > 65536n) {
            blocks.set(bEven, [preEdit[1][i - 1] - (BigInt(bEven - 1) * 65536n)])
          } else {
            blocks.set(bEven, [preEdit[1][i - 1]])
          }
        }
        blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i]])
      } else if (bEven !== bOdd) {
        if (blocks.has(bEven)) {
          if (preEdit[1][i - 1] > 65536n) {
            blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i - 1] - (BigInt(bEven - 1) * 65536n)])
          } else {
            blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i - 1]])
          }
        } else {
          if (preEdit[1][i - 1] > 65536n) {
            blocks.set(bEven, [preEdit[1][i - 1] - (BigInt(bEven - 1) * 65536n)])
          } else {
            blocks.set(bEven, [preEdit[1][i - 1]])
          }
        }
        if (preEdit[1][i - 1] > 65536) {
          blocks.set(bEven, [...blocks.get(bEven), 65536n * BigInt(bEven) - preEdit[1][i - 1]])
        } else {
          blocks.set(bEven, [...blocks.get(bEven), 65536n - preEdit[1][i - 1]])
        }
        const lastKey = [...blocks.keys()].pop()
        const x = (preEdit[1][i] / 65536n)
        if (preEdit[1][i] > 65536n) {
          for (let j = lastKey + 1; j < Number(x + 1n); j++) {
            blocks.set(j, [0n, 65536n])
          }
        }
        blocks.set(bOdd, [0n])
        if (Number(x) > 0) {
          if (preEdit[1][i - 1] > 65536) {
            blocks.set(bOdd, [...blocks.get(bOdd), preEdit[1][i] - (65536n * BigInt(bEven) - preEdit[1][i - 1])])
          } else {
            blocks.set(bOdd, [...blocks.get(bOdd), preEdit[1][i] - (65536n * x - preEdit[1][i - 1])])
          }
        } else {
          if (preEdit[1][i - 1] > 65536) {
            blocks.set(bOdd, [...blocks.get(bOdd), preEdit[1][i] - (65536n * BigInt(bEven) - preEdit[1][i - 1])])
          } else {
            blocks.set(bOdd, [...blocks.get(bOdd), preEdit[1][i] - (65536n * (x + 1n) - preEdit[1][i - 1])])
          }
        }
      }
    }
  }
  return [blocks, preEdit[2]]
}

/**
 * decryptEdit is used to decrypt the parts received from the edit lists
 * @param {*} headerInformation 2 dim array containing the header Informations, needed to decrypt the data
 * @param {*} encryptedData encrypted data whitch is about to be decrypted
 * @param {*} chacha20poly1305 decryption method
 */
async function * decryptEdit (headerInformation, encryptedData, chacha20poly1305) {
  // 3.Step entschlüssle nur die gebrauchten blöcke
  const blocks = await calculateEditlist(headerInformation)
  for await (const val of decryptionBlocks(encryptedData, Array.from(blocks[0].keys()), headerInformation, chacha20poly1305)) {
    const edit = dec.applyEditlist(blocks[0].get(val[2]), val[0])
    yield await Promise.resolve(edit)
  }
  if (blocks[1] === true) {
    for (let i = headerInformation[4] + 65564 * Math.max(...blocks[0].keys()); i < encryptedData.length; i = i + 65564) {
      const nonce = await encryptedData.subarray(i, i + 12)
      const enc = await encryptedData.subarray(i + 12, i + 12 + dec.SEGMENT_SIZE + 16)
      const plaintext = chacha20poly1305.open(nonce, enc)
      yield await Promise.resolve(plaintext)
    }
  }
}
