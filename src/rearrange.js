import * as enc from './encryption.js'
import * as dec from './decryption.js'

const SEGMENT_SIZE = 65536
const PacketTypeDataEnc = '0000'
const PacketTypeEditList = '1000'

export async function rearrange (infile, seckey, pubkey, editlist) {
  try {
    const fullEnc = []
    const header = await infile.subarray(0, 10000)
    const headerPackets = dec.parse(header)
    const decryptedPackets = dec.decryptHeader(headerPackets[0], seckey)
    const rearranged = rearrangement(decryptedPackets, editlist, headerPackets, pubkey, seckey, fullEnc, infile)
    return rearranged
  } catch (e) {
    console.trace('Data could not be rearranged.')
  }
}

export async function streamRearrange (header, seckey, pubkey, editlist) {
  const headerPackets = dec.parse(header)
  const decryptedPackets = await dec.decryptHeader(headerPackets[0], seckey)
  const sessionk = decryptedPackets[0][0].subarray(8)
  const newEditPacket = await headerRearrange(decryptedPackets[0], editlist, headerPackets[1].length, pubkey, seckey, sessionk)
  if(newEditPacket !== undefined){
    return [newEditPacket, headerPackets[2]]
  }
}

async function headerRearrange (decPackets, editlist, inputlänge, pubkeys, seckey, key) {
  try {
    const encryptionMethod = new Uint32Array([0])
    const partitionPacket = partitionPackets(decPackets)
    // no editlist in old header
    if (partitionPacket[1].length === 0) {
      const encHeader = await enc.encryptionEdit(editlist, encryptionMethod, key, pubkeys, seckey)
      return encHeader
    } else {
      const oldEdit = partitionPacket[1][0]
      const big64Oldedit = new BigUint64Array(oldEdit.buffer)
      let b
      const outOfRange = []
      // new header with multiple editlists
      if (Array.isArray(editlist[0]) === true) {
        const multiEdit = await rearrHeaderMultiEdits(editlist, big64Oldedit, inputlänge, b, outOfRange, encryptionMethod, key, pubkeys, seckey)
        return multiEdit
      } else {
        // new header with single edit list
        const singleEdit = await rearrHeaderEdit(big64Oldedit, inputlänge, b, editlist, decPackets, seckey, pubkeys)
        return singleEdit
      }
    }
  } catch (e) {
    console.trace('header could not be rearranged.')
  }
}

function calculateLastEditOld (inputlänge, big, b) {
  try {
    let fit = 0
    let counter = 0
    while (fit <= inputlänge - 65564) {
      fit = fit + 65564
      counter++
    }
    if (fit < inputlänge) {
      counter++
    }
    let sum = BigInt(0)
    b = new BigUint64Array(big.length)
    b.set(big.slice(1))
    b.forEach(x => { sum += x })
    const last = BigInt(inputlänge) - BigInt(counter * 28) - sum
    b.set([last], big.length - 1)
    return [b, big]
  } catch (e) {
    console.trace('old edit list could not be analysed.')
  }
}

function calculaLastEditNew (inputlänge, editlist) {
  try {
    let sum = 0
    let fit = 0
    let counter = 0
    while (fit <= inputlänge - 65564) {
      fit = fit + 65564
      counter++
    }
    if (fit < inputlänge) {
      counter++
    }
    editlist.forEach(x => { sum += x })
    editlist.push(inputlänge - counter * 28 - sum)
    return editlist
  } catch (e) {
    console.trace('new edit list could not be analysed.')
  }
}

export function parts (edits) {
  try {
    let position = BigInt(0)
    const allowed = []
    for (let i = 0; i < edits.length; i = i + 2) {
      const discard = edits[i]
      position = position + BigInt(discard)
      if (i + 1 < edits.length) {
        const keep = BigInt(edits[i + 1])
        allowed.push([position, position + keep])
        position = position + BigInt(keep)
      } else {
        const keep = BigInt(edits[i + 1])
        allowed.push([position, position + keep])
      }
    }
    return allowed
  } catch (e) {
    console.trace('decryptable parts could not be computed.')
  }
}

function checkParts (allowed, newEdit) {
  try {
    const checked = []
    for (let i = 0; i < allowed.length; i++) {
      let fits = 0
      for (let j = 0; j < newEdit.length; j++) {
        if (allowed[i][0] <= BigInt(newEdit[j][0]) && allowed[i][1] >= BigInt(newEdit[j][1])) {
          checked.push(newEdit[j])
          fits++
        }
      }
      if (fits < 0) {
        console.trace('unencryptable data')
      }
    }
    return checked
  } catch (e) {
    console.trace('data acess could not be checked.')
  }
}

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
      } else {
        throw Error('Invalid packet type')
      }
    }
    return [encPackets, editPackets]
  } catch (e) {
    console.trace('Packages could not be partitionated.')
  }
}

async function rearrangement (decryptedPackets, editlist, headerPackets, pubkey, seckey, fullEnc, infile) {
  try {
    const sessionk = decryptedPackets[0][0].subarray(8)
    const newEditPacket = await headerRearrange(decryptedPackets[0], editlist, headerPackets[1].length, pubkey, seckey, sessionk)
    if (newEditPacket) {
      fullEnc.push(newEditPacket[0])
      const chunksize = SEGMENT_SIZE
      let offset = headerPackets[2]
      while (offset < infile.length) {
        const chunkfile = await infile.subarray(offset, offset + chunksize)
        fullEnc.push(chunkfile)
        offset += chunksize
      }
      return fullEnc
    }
  } catch (e) {
    console.trace('Rearrangment could not be computed.')
  }
}

async function rearrHeaderMultiEdits (editlist, big64Oldedit, inputlänge, b, outOfRange, encryptionMethod, key, pubkeys, seckey) {
  for (let i = 0; i < editlist.length; i++) {
    if ((big64Oldedit.length - 1) % 2 !== 0) {
      const lastEdit = calculateLastEditOld(inputlänge, big64Oldedit, b)
      b = lastEdit[0]
      big64Oldedit = lastEdit[1]
    } else {
      b = big64Oldedit.slice(1)
    }
    if ((editlist[i].length) % 2 !== 0) {
      editlist[i] = calculaLastEditNew(inputlänge, editlist[i])
    }
    // Berechnung, bereiche der beiden editlisten
    const allowed = parts(b)
    const newEdit = parts(editlist[i])
    // Berechne, ob Bereiche ineinander passen
    const checked = checkParts(allowed, newEdit)
    if (checked.length === newEdit.length) {
      for (let i = 0; i < checked.length; i++) {
        if (i === 0) {
          outOfRange.push(0)
        }
        if (checked[i][0] !== newEdit[i][0] || checked[i][1] !== newEdit[i][1]) {
          outOfRange.push(1)
        }
      }
    }
  }
  if (!outOfRange.includes(1)) {
    const s = await enc.encryptionEdit(editlist, encryptionMethod, key, pubkeys, seckey)
    return [s]
  }
}

async function rearrHeaderEdit (big64Oldedit, inputlänge, b, editlist, decPackets, seckey, pubkeys) {
  // abfragen ob die alte und/oder neue editliste ungerade sind/ist
  if ((big64Oldedit.length - 1) % 2 !== 0) {
    const lastEdit = calculateLastEditOld(inputlänge, big64Oldedit, b)
    b = lastEdit[0]
    big64Oldedit = lastEdit[1]
  } else {
    b = big64Oldedit.slice(1)
  }
  if ((editlist.length) % 2 !== 0) {
    editlist = calculaLastEditNew(inputlänge, editlist)
  }
  // Berechnung, bereiche der beiden editlisten
  const allowed = parts(b)
  const newEdit = parts(editlist)
  // Berechne, ob Bereiche ineinander passen
  const checked = checkParts(allowed, newEdit)
  let unallowedEdit
  if (checked.length === newEdit.length) {
    for (let i = 0; i < checked.length; i++) {
      if (i === 0) {
        unallowedEdit = 0
      }
      if (checked[i][0] !== newEdit[i][0] || checked[i][1] !== newEdit[i][1]) {
        unallowedEdit = 1
      }
    }
    if (unallowedEdit === 0) {
      const newEditPacket = enc.makePacketEditList(editlist)
      const encr = await enc.headerEncrypt([decPackets[0], newEditPacket], seckey, pubkeys)
      const serializedData = enc.serialize(encr[0], encr[1], encr[2], encr[3])
      return serializedData
    }
  }
}
