const keygen = require('./keygen')
const keyfiles = require('./check_keyfiles')
const encryption = require('./encryption')
const decryption = require('./decryption')
const reeencryption = require('./reeencryption')
const rearrangment = require('./rearrange')

const acc = document.getElementsByClassName('accordion')
let i

for (i = 0; i < acc.length; i++) {
  acc[i].addEventListener('click', function () {
    /* Toggle between adding and removing the "active" class,
    to highlight the button that controls the panel */
    this.classList.toggle('active')

    /* Toggle between hiding and showing the active panel */
    const panel = this.nextElementSibling
    if (panel.style.display === 'block') {
      panel.style.display = 'none'
    } else {
      panel.style.display = 'block'
    }
  })
}

// KeyGen
const button = document.getElementById('submit')
button.addEventListener('click', async function (event) {
  const password = await document.getElementById('psw').value
  const result = await keygen.keygen(password)
  console.log(result)
})

// Encryption
document.getElementById('button').onclick = function () { myFunction() }

function myFunction () {
  const file = document.getElementById('input').textContent
  console.log(file)
  const file2 = document.getElementById('input2')
  const file3 = document.getElementById('input3')
  const password = document.getElementById('psw2').value
  const blocks = document.getElementById('block2').value
  const edit = document.getElementById('editlist').value
  const ed = null;

  (async () => {
    const seckeyFile = await file.text()
    const pubkeyFile = await file2.text()
    const block = null
    const keys = await keyfiles.encryption_keyfiles([seckeyFile, pubkeyFile], password)
    const header = await encryption.encHead(keys[0], [keys[1], keys[2]], ed)
    console.log(header[0])
    const chunksize = 65536
    let counter = 0
    let offset = 0
    while (offset < file3.size) {
      counter++
      const chunkfile = await file3.slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      const encryptedtext = await encryption.encryption(header, new Uint8Array(chunk), counter, block)
      const encoder = new TextEncoder()
      if (encryptedtext) {
        console.log(encoder.encode(encryptedtext))
      }

      offset += chunksize
    }
    console.log('all done')
  })()
}
/*
const encr = document.getElementById('button')
encr.addEventListener('click', async function (event) {
  const file = document.getElementById('input')
  const file2 = document.getElementById('input2')
  const file3 = document.getElementById('input3')
  const password = document.getElementById('psw2').value
  const blocks = document.getElementById('block2').value
  const edit = document.getElementById('editlist').value
  const ed = null;

  (async () => {
    const pubkeyFile = await file.text()
    const pubkeyFile2 = await file2.text()
    const seckeyFile = await file3.text()
    const block = null
    const fileContents = document.getElementById('encfile')
    const keys = await keyfiles.encryption_keyfiles([seckeyFile, pubkeyFile, pubkeyFile2], password)
    const header = await encryption.encHead(keys[0], [keys[1], keys[2]], ed)
    console.log(header[0])
    // fileContents.innerText += header[0]
    const chunksize = 65536
    let counter = 0
    let offset = 0
    while (offset < file3.size) {
      counter++
      const chunkfile = await file3.slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      const encryptedtext = await encryption.encryption(header, new Uint8Array(chunk), counter, block)
      const encoder = new TextEncoder()
      if (encryptedtext) {
        console.log(encoder.encode(encryptedtext))
        // fileContents.innerText += encoder.encode(encryptedtext)
      }

      offset += chunksize
    }
    console.log('all done')
  })()
})

/*
// Decryption
document.getElementById('input').addEventListener('change', function (e) {
  const file = document.getElementById('input').files[0]
  const file2 = document.getElementById('input').files[1]
  const password = document.getElementById('psw').value
  const blocks = document.getElementById('block').value
  let block = [] | null;
  (async () => {
    const seckeyFile = await file.text()
    if (blocks === '') {
      block = null
    } else if (blocks.includes(',')) {
      block = []
      const b = blocks.split(',')
      for (let i = 0; i < b.length; i++) {
        block.push(Number(b[i]))
      }
    } else {
      block = blocks
    }
    const fileContents = document.getElementById('filecontents')
    const keys = await keyfiles.encryption_keyfiles([seckeyFile], password)
    const headerChunk = await file2.slice(0, 1000)
    const chunkHeader = await headerChunk.arrayBuffer()
    const header = await decryption.header_deconstruction(new Uint8Array(chunkHeader), keys[0])
    const chunksize = 65564
    let counter = 0
    let offset = header[4]
    while (offset < file2.size) {
      counter++
      const chunkfile = await file2.slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      const plaintext = await decryption.decrypption(header, new Uint8Array(chunk), counter, block)
      const decoder = new TextDecoder()
      if (plaintext) {
        fileContents.innerText += decoder.decode(plaintext)
      }
      offset += chunksize
    }
    console.log('all done')
  })()
})

// KeyGen
const button = document.getElementById('submit')
button.addEventListener('click', async function (event) {
  const password = await document.getElementById('psw2').value
  const result = await keygen.keygen(password)
  const erg = result
  const pubkey = document.getElementById('pubkeyfile')
  pubkey.innerText = erg[1]
  const seckey = document.getElementById('seckeyfile')
  seckey.innerText = erg[0]
})

// Encryption
document.getElementById('input2').addEventListener('change', function (e) {
  const file = document.getElementById('input2').files[0]
  const file2 = document.getElementById('input2').files[1]
  const file3 = document.getElementById('input2').files[2]
  const file4 = document.getElementById('input2').files[3]
  const password = document.getElementById('psw3').value
  const blocks = document.getElementById('block2').value
  const edit = document.getElementById('block3').value;

  (async () => {
    const pubkeyFile = await file.text()
    const pubkeyFile2 = await file2.text()
    const seckeyFile = await file3.text()
    let block = null | []
    if (blocks === '') {
      block = null
    } else if (blocks.includes(',')) {
      block = []
      const b = blocks.split(',')
      for (let i = 0; i < b.length; i++) {
        block.push(Number(b[i]))
      }
    } else {
      block = blocks
    }
    let editlist = []
    let ed = []
    if (edit.includes(';')) {
      const step = edit.split(';')
      for (let i = 0; i < step.length; i++) {
        editlist = step[i].split(',')
        for (let j = 0; j < editlist.length; j++) {
          if (j === 0) {
            ed.push([Number(editlist[j])])
          } else {
            ed[i].push(Number(editlist[j]))
          }
        }
      }
    } else if (edit === '') {
      ed = null
    } else {
      editlist = edit.split(',')
      console.log(editlist)
      for (let i = 0; i < editlist.length; i++) {
        ed.push(Number(editlist[i]))
      }
    }
    const fileContents = document.getElementById('encfile')
    const keys = await keyfiles.encryption_keyfiles([seckeyFile, pubkeyFile, pubkeyFile2], password)
    const header = await encryption.encHead(keys[0], [keys[1], keys[2]], ed)
    fileContents.innerText += header[0]
    const chunksize = 65536
    let counter = 0
    let offset = 0
    while (offset < file4.size) {
      counter++
      const chunkfile = await file4.slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      const encryptedtext = await encryption.encryption(header, new Uint8Array(chunk), counter, block)
      const encoder = new TextEncoder()
      if (encryptedtext) {
        fileContents.innerText += encoder.encode(encryptedtext)
      }

      offset += chunksize
    }
    console.log('all done')
  })()
})

// Reencryption
document.getElementById('input3').addEventListener('change', function (e) {
  const file = document.getElementById('input3').files[0]
  const file2 = document.getElementById('input3').files[1]
  const file3 = document.getElementById('input3').files[2]
  const password = document.getElementById('psw4').value;

  (async () => {
    const pubkeyFile = await file2.text()
    const seckeyFile = await file.text()
    const fileContents = document.getElementById('reencryption')
    const keys = await keyfiles.encryption_keyfiles([seckeyFile, pubkeyFile], password)
    const headerChunk = await file3.slice(0, 1000)
    const chunkHeader = await headerChunk.arrayBuffer()
    const reencryptHeader = await reeencryption.streamReencryptHeader(new Uint8Array(chunkHeader), [keys[1]], keys[0])
    fileContents.innerText += reencryptHeader
    const chunksize = 65564
    let offset = reencryptHeader[1]
    while (offset < file3.size) {
      const chunkfile = await file3.slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      fileContents.innerText += new Uint8Array(chunk)
      offset += chunksize
    }
  })()
})

// Rearrangement
document.getElementById('input4').addEventListener('change', function (e) {
  const file = document.getElementById('input4').files[0]
  const file2 = document.getElementById('input4').files[1]
  const file3 = document.getElementById('input4').files[2]
  const password = document.getElementById('psw5').value
  const edit = document.getElementById('block4').value
  let editlist = []
  let ed = []
  if (edit.includes(';')) {
    const step = edit.split(';')
    for (let i = 0; i < step.length; i++) {
      editlist = step[i].split(',')
      for (let j = 0; j < editlist.length; j++) {
        if (j === 0) {
          ed.push([Number(editlist[j])])
        } else {
          ed[i].push(Number(editlist[j]))
        }
      }
    }
  } else if (edit === '') {
    ed = null
  } else {
    editlist = edit.split(',')
    for (let i = 0; i < editlist.length; i++) {
      ed.push(Number(editlist[i]))
    }
  }
  (async () => {
    const pubkeyFile = await file2.text()
    const seckeyFile = await file.text()
    const fileContents = document.getElementById('rearrange')
    const keys = await keyfiles.encryption_keyfiles([seckeyFile, pubkeyFile], password)
    const headerChunk = await file3.slice(0, 1000)
    const chunkHeader = await headerChunk.arrayBuffer()
    const rearrangeHeader = await rearrangment.streamRearrange(new Uint8Array(chunkHeader), keys[0], [keys[1]], ed)
    fileContents.innerText += rearrangeHeader
    const chunksize = 65564
    let offset = rearrangeHeader[1]
    while (offset < file3.size) {
      const chunkfile = await file3.slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      fileContents.innerText += new Uint8Array(chunk)
      offset += chunksize
    }
  })()
}) */
