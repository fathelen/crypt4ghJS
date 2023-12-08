/* eslint no-undef: */
const index = require('crypt4gh_js')

const mergedArray = function (ArrayList) {
  let length = 0
  ArrayList.forEach(item => {
    length += item.length
  })
  const mergedArray = new Uint8Array(length)
  let offset = 0
  ArrayList.forEach(item => {
    mergedArray.set(item, offset)
    offset += item.length
  })
  return mergedArray
}

const fs = require('fs')
const testDataUnencrypted = fs.readFileSync('testData\\abcd.txt', 'utf8')
const testDataEncrypted = fs.readFileSync('testData\\abcdEncrypted.crypt4gh')
const testDataPlain = fs.readFileSync('testData\\edit.crypt4gh')
const test4edit = fs.readFileSync('testData\\edit4values.crypt4gh')
const test6edit = fs.readFileSync('testData\\edit6values.crypt4gh')
const test8edit = fs.readFileSync('testData\\edit8values.crypt4gh')
const testCase3 = fs.readFileSync('testData\\editCase3values.crypt4gh')
const testCase4 = fs.readFileSync('testData\\editCase4values.crypt4gh')
const testCase5 = fs.readFileSync('testData\\editCase5.crypt4gh')
const testCase6 = fs.readFileSync('testData\\editCase6.crypt4gh')
const testCase7 = fs.readFileSync('testData\\editCase7.crypt4gh')
const testOdd1 = fs.readFileSync('testData\\editOdd1.crypt4gh')
const testOdd11 = fs.readFileSync('testData\\editOdd1_1.crypt4gh')
const testOdd2 = fs.readFileSync('testData\\editOdd2.crypt4gh')
const testOdd3 = fs.readFileSync('testData\\editOdd3.crypt4gh')
const testDataEncryptedEdit = fs.readFileSync('testData\\encEdit.crypt4gh')
const testDataEncMultiEdit = fs.readFileSync('testData\\encMultiEdit.crypt4gh')
const testDataEncEditOdd = fs.readFileSync('testData\\encEditOdd.crypt4gh')
const testDataBlock = fs.readFileSync('testData\\encBlock.crypt4gh')
const testDataReenc = fs.readFileSync('testData\\ReEnc.crypt4gh')
const testDataRearrNoEdit = fs.readFileSync('testData\\Rearr_noEdit.crypt4gh')
const testDataRearrEdit = fs.readFileSync('testData\\Rearr_Edit.crypt4gh')
const testDataRearrMultiEdit = fs.readFileSync('testData\\Rearr_MultiEdit.crypt4gh')
const seckeyFileKey = new Uint8Array([20, 185, 204, 26, 245, 237, 159, 85, 129, 196, 166, 241, 27, 160, 54, 218, 89, 96, 153, 190, 9, 141, 139, 109, 142, 182, 83, 62, 107, 180, 10, 203])
const seckey = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAg4BW6LpwKHBQN0MCZgjPtDafcGbN5wRmUSrIwEcN4te0=\n-----END CRYPT4GH PRIVATE KEY-----\n'
const pubkey = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nGER04WfJXzPHiCWe94CHlMY6sp6zwWpAehA0MMHjdVQ=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const pubkeyPass = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nvHrVpBpFLpX/OquK2Ze4Mfzb8aVrn05XmTgT4ymVwzE=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const seckeyPass = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAMHZyZm0wb3JrM2E5d2QyeQARY2hhY2hhMjBfcG9seTEzMDUAPHUyY2lhbDQ1dWZydxzqFWikrPHQc6dKqWySS59BoMAe1L0FRmBXnwPd80N4fJBJS5f+vnmlA+JZ8qCpow==\n-----END CRYPT4GH PRIVATE KEY-----\n'
const unencryptedText = Buffer.from('abcdefghijklmnopqrstuvwxyz')
const encSeckey = new Uint8Array([224, 21, 186, 46, 156, 10, 28, 20, 13, 208, 192, 153, 130, 51, 237, 13, 167, 220, 25, 179, 121, 193, 25, 148, 74, 178, 48, 17, 195, 120, 181, 237])
const encPubkey = new Uint8Array([24, 68, 116, 225, 103, 201, 95, 51, 199, 136, 37, 158, 247, 128, 135, 148, 198, 58, 178, 158, 179, 193, 106, 64, 122, 16, 52, 48, 193, 227, 117, 84])
const encSeckeyPass = new Uint8Array([0, 78, 220, 95, 54, 181, 47, 52, 219, 136, 71, 191, 133, 251, 22, 200, 52, 195, 145, 195, 151, 193, 84, 12, 220, 215, 72, 117, 163, 211, 226, 189])
const encPubkeyPass = new Uint8Array([188, 122, 213, 164, 26, 69, 46, 149, 255, 58, 171, 138, 217, 151, 184, 49, 252, 219, 241, 165, 107, 159, 78, 87, 153, 56, 19, 227, 41, 149, 195, 49])

// test key generation without password
test('generate secret/ public key pair without password', async () => {
  const encKeys = await index.keygen.keygen('')
  expect(encKeys).toBeInstanceOf(Array)
  expect(typeof (encKeys[0])).toEqual('string')
  expect(typeof (encKeys[1])).toEqual('string')
  expect(encKeys[0]).toMatch(/-----BEGIN CRYPT4GH PRIVATE KEY-----/)
  expect(encKeys[0]).toMatch(/-----END CRYPT4GH PRIVATE KEY-----/)
  expect(encKeys[1]).toMatch(/-----BEGIN CRYPT4GH PUBLIC KEY-----/)
  expect(encKeys[1]).toMatch(/-----END CRYPT4GH PUBLIC KEY-----/)
})

// test key generation with password
test('generate secret/ public key pair with password', async () => {
  const encKeys = await index.keygen.keygen('password')
  expect(encKeys).toBeInstanceOf(Array)
  expect(typeof (encKeys[0])).toEqual('string')
  expect(typeof (encKeys[1])).toEqual('string')
  expect(encKeys[0]).toMatch(/-----BEGIN CRYPT4GH PRIVATE KEY-----/)
  expect(encKeys[0]).toMatch(/-----END CRYPT4GH PRIVATE KEY-----/)
  expect(encKeys[1]).toMatch(/-----BEGIN CRYPT4GH PUBLIC KEY-----/)
  expect(encKeys[1]).toMatch(/-----END CRYPT4GH PUBLIC KEY-----/)
})

// test encrypt keyfiles without password
test('decrpt secret key and public key without password', async () => {
  const keys = await index.keyfiles.encryption_keyfiles([seckey, pubkey])
  expect(keys[0]).toBeInstanceOf(Uint8Array)
  expect(keys[1]).toBeInstanceOf(Uint8Array)
  expect(keys[0].length).toEqual(new Uint8Array(32).length)
  expect(keys[1].length).toEqual(new Uint8Array(32).length)
})

// test decrypt keyfiles with password
test('decrpt secret key and public key with password', async () => {
  const keys = await index.keyfiles.encryption_keyfiles([seckeyPass, pubkeyPass], 'gunpass')
  expect(keys[0]).toBeInstanceOf(Uint8Array)
  expect(keys[1]).toBeInstanceOf(Uint8Array)
  expect(keys[0].length).toEqual(new Uint8Array(32).length)
  expect(keys[1].length).toEqual(new Uint8Array(32).length)
})

// encryption without password, editlist or blocks
test('encryption without password, editlist or block', async () => {
  const block = null
  const edit = null
  for await (const val of index.encryption.encryption(Buffer.from(testDataUnencrypted), encSeckey, [encPubkey], block, edit)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // fs.appendFileSync('testData\\edit1.crypt4gh', val)
  }
})

// encryption with password, without editlist or blocks
test('encryption with password,without editlist or block', async () => {
  edit = null
  block = null
  for await (const val of index.encryption.encryption(Buffer.from(testDataUnencrypted), encSeckeyPass, [encPubkeyPass], block, edit)) {
    expect(val).toBeInstanceOf(Uint8Array)
  }
})

// encryption without password and blocks with editlist
test('encryption without password and blocks with editlist', async () => {
  edit = [0, 70000, 5]
  block = null
  for await (const val of index.encryption.encryption(Buffer.from(testDataUnencrypted), encSeckey, [encPubkey], block, edit)) {
    // fs.appendFileSync('testData\\editOdd1_1.crypt4gh', val)
    expect(val).toBeInstanceOf(Uint8Array)
  }
})

// encryption without password and blocks with editlist (odd)
test('encryption without password and blocks with editlist(odd)', async () => {
  edit = [0, 10, 10]
  block = null
  for await (const val of index.encryption.encryption(unencryptedText, encSeckey, [encPubkey], block, edit)) {
    expect(val).toBeInstanceOf(Uint8Array)
  }
})

// encryption with password and editlist, without blocks
test('encryption with password and editlist, without blocks', async () => {
  edit = [0, 5]
  block = null
  for await (const val of index.encryption.encryption(unencryptedText, encSeckeyPass, [encPubkeyPass], block, edit)) {
    expect(val).toBeInstanceOf(Uint8Array)
  }
})

// encryption without password and blocks with multiple editlist
test('encryption without password and blocks with multiple editlist', async () => {
  edit = [[0, 10], [0, 4]]
  block = null
  for await (const val of index.encryption.encryption(unencryptedText, encSeckey, [encPubkey, encPubkeyPass], block, edit)) {
    expect(val).toBeInstanceOf(Uint8Array)
  }
})

// encryption with password and multiple editlist, without blocks
test('encryption with password and multiple editlist, without blocks', async () => {
  edit = [[0, 5], [0, 49]]
  block = null
  for await (const val of index.encryption.encryption(unencryptedText, encSeckeyPass, [encPubkeyPass, encPubkeyPass], block, edit)) {
    expect(val).toBeInstanceOf(Uint8Array)
  }
})

// encryption without password and editlist, with block
test('encryption without password and editlist, with block', async () => {
  edit = null
  block = [1, 4]
  for await (const val of index.encryption.encryption(Buffer.from(testDataUnencrypted), encSeckey, [encPubkey], block, edit)) {
    expect(val).toBeInstanceOf(Uint8Array)
  }
})

// encryption with password and block, without editlist
test('encryption with password and block, without editlist', async () => {
  edit = null
  block = [1]
  for await (const val of encryptedText = index.encryption.encryption(unencryptedText, encSeckeyPass, [encPubkeyPass], block, edit)) {
    expect(val).toBeInstanceOf(Uint8Array)
  }
})

// decryption without password, editlist, encblocks or decblocks
test('decryption without password, editlist, encblocks or decblocks', async () => {
  blocks = null
  for await (const val of index.decryption.decryption(Uint8Array.from(testDataPlain), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with editlist
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(test4edit), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with editlist (6)
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(test6edit), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with editlist (8)
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(test8edit), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with odd editlist (1)
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testOdd1), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with odd editlist (11)
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testOdd11), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with odd editlist (2)
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testOdd2), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with odd editlist (3)
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testOdd3), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with editlist testcase 3
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testCase3), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with editlist testcase 4
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testCase4), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with editlist testcase 5
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testCase5), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with editlist testcase 6
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testCase6), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with editlist testcase 7
test('decryption without password, encblocks or decblocks, with editlist', async () => {
  blocks = null
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testCase7), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption without password, encblocks or decblocks, with multiple editlist
test('decryption without password, encblocks or decblocks, with multiple editlist (Person 1)', async () => {
  blocks = null
  for await (const val of decryptedText = await index.decryption.decryption(Uint8Array.from(testDataEncMultiEdit), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    const textdecoder = new TextDecoder()
    expect(textdecoder.decode(val)).toMatch('abcdefghij')
  }
})

// decryption without password, encblocks or decblocks, with multiple editlist
test('decryption without password, encblocks or decblocks, with multiple editlist (Person 2)', async () => {
  blocks = null
  for await (const val of decryptedText = await index.decryption.decryption(Uint8Array.from(testDataEncMultiEdit), encSeckeyPass, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    const textdecoder = new TextDecoder()
    expect(textdecoder.decode(val)).toMatch('abcd')
  }
})

// decryption without password, encblocks or decblocks, with editlist odd
test('decryption without password, encblocks or decblocks, with editlist odd', async () => {
  blocks = null
  for await (const val of decryptedText = await index.decryption.decryption(Uint8Array.from(testDataEncEditOdd), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    const textdecoder = new TextDecoder()
    expect(textdecoder.decode(val)).toMatch('abcdefghijuvwxyz')
  }
})

// decryption with block
test('decryption with block', async () => {
  blocks = null
  for await (const val of decryptedText = await index.decryption.decryption(Uint8Array.from(testDataBlock), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// decryption with decblock
test('decryption with decblock', async () => {
  blocks = [1]
  for await (const val of encryptedText = index.decryption.decryption(Uint8Array.from(testDataBlock), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    // const textdecoder = new TextDecoder()
    // console.log(textdecoder.decode(val))
  }
})

// reencryption
test('reeencryption', async () => {
  for await (const val of encryptedText = index.reeencryption.reencrypt(Uint8Array.from(testDataEncrypted), [encPubkey], seckeyFileKey)) {
    expect(val).toBeInstanceOf(Uint8Array)
  }
})

test('decryption of reeencrypted', async () => {
  blocks = null
  for await (const val of decryptedText = await index.decryption.decryption(Uint8Array.from(testDataReenc), encSeckey, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
  }
})

// rearrangment ohne edit vorher
test('rearrangment without edit', async () => {
  const editlist = [0, 9]
  const rearrangedText = await index.rearrangment.rearrange(Uint8Array.from(testDataEncrypted), seckeyFileKey, [encPubkeyPass], editlist)
  expect(rearrangedText).toBeInstanceOf(Array)
  expect(rearrangedText[0]).toBeInstanceOf(Uint8Array)
  fs.writeFileSync('testData\\Rearr_noEdit.crypt4gh', mergedArray(rearrangedText))
})

test('decryption of rearrangment without edit', async () => {
  blocks = null
  for await (const val of decryptedText = await index.decryption.decryption(Uint8Array.from(testDataRearrNoEdit), encSeckeyPass, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    const textdecoder = new TextDecoder()
    expect(textdecoder.decode(val)).toBe('faaaaaaaa')
  }
})

// rearrangment with edit
test('rearrangment with edit', async () => {
  const editlist = [0, 9]
  const rearrangedText = await index.rearrangment.rearrange(Uint8Array.from(testDataEncryptedEdit), encSeckey, [encPubkeyPass], editlist)
  expect(rearrangedText).toBeInstanceOf(Array)
  expect(rearrangedText[0]).toBeInstanceOf(Uint8Array)
  fs.writeFileSync('testData\\Rearr_Edit.crypt4gh', mergedArray(rearrangedText))
})

test('decryption of rearrangment with edit', async () => {
  blocks = null
  for await (const val of decryptedText = await index.decryption.decryption(Uint8Array.from(testDataRearrEdit), encSeckeyPass, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    const textdecoder = new TextDecoder()
    expect(textdecoder.decode(val)).toBe('abcdefghi')
  }
})

// rearrangment with multi edit
test('rearrangment with multi edit', async () => {
  const editlist = [0, 4]
  const rearrangedText = await index.rearrangment.rearrange(Uint8Array.from(testDataEncMultiEdit), encSeckey, [encPubkeyPass], editlist)
  expect(rearrangedText).toBeInstanceOf(Array)
  expect(rearrangedText[0]).toBeInstanceOf(Uint8Array)
  fs.writeFileSync('testData\\Rearr_MultiEdit.crypt4gh', mergedArray(rearrangedText))
})

test('decryption of rearrangment with edit', async () => {
  blocks = null
  for await (const val of decryptedText = await index.decryption.decryption(Uint8Array.from(testDataRearrMultiEdit), encSeckeyPass, blocks)) {
    expect(val).toBeInstanceOf(Uint8Array)
    const textdecoder = new TextDecoder()
    expect(textdecoder.decode(val)).toBe('abcd')
  }
})

// rearrangment with edit out of range
test('rearrangment with edit out of range', async () => {
  const editlist = [0, 12]
  const rearrangedText = await index.rearrangment.rearrange(Uint8Array.from(testDataEncryptedEdit), encSeckey, [encPubkeyPass], editlist)
  expect(rearrangedText).toBe(undefined)
})

// edit and block (not compatible)
test('encryption with edit and block', async () => {
  edit = [0, 5]
  block = [1]
  const encryptedText = await index.encryption.encryption(Buffer.from(testDataUnencrypted), encSeckey, [encPubkey], block, edit)
  expect(encryptedText).not.toBe([])
})
