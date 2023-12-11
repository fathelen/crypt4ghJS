/* eslint no-undef: */
const index = require('crypt4gh_js')
const fs = require('fs')

// const encSeckey = new Uint8Array([224, 21, 186, 46, 156, 10, 28, 20, 13, 208, 192, 153, 130, 51, 237, 13, 167, 220, 25, 179, 121, 193, 25, 148, 74, 178, 48, 17, 195, 120, 181, 237])
// const encPubkey = new Uint8Array([24, 68, 116, 225, 103, 201, 95, 51, 199, 136, 37, 158, 247, 128, 135, 148, 198, 58, 178, 158, 179, 193, 106, 64, 122, 16, 52, 48, 193, 227, 117, 84])
const encSeckeyPass = new Uint8Array([0, 78, 220, 95, 54, 181, 47, 52, 219, 136, 71, 191, 133, 251, 22, 200, 52, 195, 145, 195, 151, 193, 84, 12, 220, 215, 72, 117, 163, 211, 226, 189])
const encPubkeyPass = new Uint8Array([188, 122, 213, 164, 26, 69, 46, 149, 255, 58, 171, 138, 217, 151, 184, 49, 252, 219, 241, 165, 107, 159, 78, 87, 153, 56, 19, 227, 41, 149, 195, 49])

test('encryption, read chunks, no edit, no blocks', async () => {
  edit = null
  block = null
  const header = index.encryption.encHeader(encSeckeyPass, [encPubkeyPass], block, edit)
  // fs.appendFileSync('testData\\readChunks.crypt4gh', header)
  expect(header).toBeInstanceOf(Uint8Array)
  if (header) {
    const readStream = fs.createReadStream('testData\\abcd.txt')
    readStream
      .on('data', async function (d) {
        const val = await index.encryption.pureEncryption(d)
        // fs.appendFileSync('testData\\readChunks.crypt4gh', val)
        await expect(val).toBeInstanceOf(Uint8Array)
      })
  }
})

test('encryption, read chunks, no edit, blocks', async () => {
  edit = null
  block = [1, 2]
  let counter = 0
  const header = index.encryption.encHeader(encSeckeyPass, [encPubkeyPass])
  // fs.appendFileSync('testData\\readChunksBlocks.crypt4gh', header)
  expect(header).toBeInstanceOf(Uint8Array)
  if (header) {
    const readStream = fs.createReadStream('testData\\abcd.txt')
    readStream
      .on('data', async function (d) {
        counter++
        if (block.includes(counter) === true) {
          const val = await index.encryption.pureEncryption(d)
          // fs.appendFileSync('testData\\readChunksBlocks.crypt4gh', val)
          await expect(val).toBeInstanceOf(Uint8Array)
        }
      })
  }
})

test('encryption, read chunks, edit, no blocks', async () => {
  edit = [0, 10]
  const header = await index.encryption.encHeaderEdit(encSeckeyPass, [encPubkeyPass], edit)
  console.log(header)
  fs.appendFileSync('testData\\readChunksEdit.crypt4gh', header[0])
  expect(header[0]).toBeInstanceOf(Uint8Array)
  if (header) {
    const readStream = fs.createReadStream('testData\\abcd.txt')
    readStream
      .on('data', async function (d) {
        const val = await index.encryption.pureEncryption(d)
        fs.appendFileSync('testData\\readChunksEdit.crypt4gh', val)
        await expect(val).toBeInstanceOf(Uint8Array)
      })
  }
})
