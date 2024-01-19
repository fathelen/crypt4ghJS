const keygen = require('./keygen')
const keyfiles = require('./check_keyfiles')
const encryption = require('./encryption')
const decryption = require('./decryption')
const reeencryption = require('./reeencryption')
const rearrangment = require('./rearrange')
const Buffer = require('buffer/').Buffer

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
/*
const button = document.getElementById('submit')
button.addEventListener('click', async function (event) {
  const password = await document.getElementById('psw').value
  const result = await keygen.keygen(password)
  console.log(result)
}) */

async function keyfile () {
  const password = await document.getElementById('psw').value
  const result = await keygen.keygen(password)
  return result
}

async function encr () {
  const c4ghtext = []
  const file = document.getElementById('input')
  const file2 = document.getElementById('input2')
  const file3 = document.getElementById('input3')
  const password = document.getElementById('psw2').value
  const blocks = document.getElementById('block2').value
  const edit = document.getElementById('editlist').value
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
    for (let i = 0; i < editlist.length; i++) {
      ed.push(Number(editlist[i]))
    }
  }
  const seckeyFile = await file.files[0].text()
  const pubkeyFile = await file2.files[0].text()
  const keys = await keyfiles.encryption_keyfiles([seckeyFile, pubkeyFile], password)
  const header = await encryption.encHead(keys[0], [keys[1]], ed)
  c4ghtext.push(header[0]
  )
  const chunksize = 65536
  let counter = 0
  let offset = 0
  while (offset < file3.files[0].size) {
    counter++
    const chunkfile = await file3.files[0].slice(offset, offset + chunksize)
    const chunk = await chunkfile.arrayBuffer()
    const encryptedtext = await encryption.encryption(header, new Uint8Array(chunk), counter, block)
    if (encryptedtext) {
      c4ghtext.push(encryptedtext)
    }

    offset += chunksize
  }
  console.log('all done')
  const buffered = Buffer.concat(c4ghtext)
  const text = new Uint8Array(buffered)
  return text
}

async function decr () {
  let decText = ''
  const file = document.getElementById('input4')
  const file2 = document.getElementById('input5')
  const password = document.getElementById('psw3').value
  const seckeyFile = await file.files[0].text()
  const keys = await keyfiles.encryption_keyfiles([seckeyFile], password)
  const headerChunk = await file2.files[0].slice(0, 1000)
  const chunkHeader = await headerChunk.arrayBuffer()
  const header = await decryption.header_deconstruction(new Uint8Array(chunkHeader), keys[0])
  const chunksize = 65564
  let counter = 0
  let offset = header[4]
  while (offset < file2.files[0].size) {
    counter++
    const chunkfile = await file2.files[0].slice(offset, offset + chunksize)
    const chunk = await chunkfile.arrayBuffer()
    const plaintext = await decryption.decrypption(header, new Uint8Array(chunk), counter)
    const decoder = new TextDecoder()
    if (plaintext) {
      decText += decoder.decode(plaintext)
    }
    offset += chunksize
  }
  console.log('all done')
  return decText
}
// Download keyfiles
document.getElementById('btn').addEventListener('click', async function () {
  const keys = await keyfile()
  const text = keys[0]
  const filename = 'secret_keyfile'
  download(filename, text)
  const text2 = keys[1]
  const filename2 = 'public_keyfile'

  download(filename2, text2)
}, false)

// Download c4gh file
document.getElementById('but').addEventListener('click', async function () {
  const enc = await encr()
  const filename = 'c4gh_file'
  saveByteArray([enc], filename)
}, false)

// Download decrypted file
document.getElementById('but2').addEventListener('click', async function () {
  const dec = await decr()
  const filename = 'decrypted_file'
  download(filename, dec)
}, false)

function download (file, text) {
  // creating an invisible element

  const element = document.createElement('a')
  element.setAttribute('href',
    'data:text/plain;charset=utf-8,' +
        encodeURIComponent(text))
  element.setAttribute('download', file)
  document.body.appendChild(element)
  element.click()

  document.body.removeChild(element)
}

const saveByteArray = (function () {
  const a = document.createElement('a')
  document.body.appendChild(a)
  a.style = 'display: none'
  return function (data, name) {
    const blob = new Blob(data, { type: 'octet/stream' })
    const url = window.URL.createObjectURL(blob)
    a.href = url
    a.download = name
    a.click()
    window.URL.revokeObjectURL(url)
  }
}())

// Encryption
/*
document.getElementById('button').onclick = function () { myFunction() }

function myFunction () {
  const fileInput = document.getElementById('input')
  const seckeyFile2 = await fileInput.files[0].text()
  const file = document.getElementById('input')
  const file2 = document.getElementById('input2')
  const file3 = document.getElementById('input3')
  const password = document.getElementById('psw2').value
  const blocks = document.getElementById('block2').value
  const edit = document.getElementById('editlist').value
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
    for (let i = 0; i < editlist.length; i++) {
      ed.push(Number(editlist[i]))
    }
  }

  (async () => {
    const seckeyFile = await file.files[0].text()
    const pubkeyFile = await file2.files[0].text()
    const keys = await keyfiles.encryption_keyfiles([seckeyFile, pubkeyFile], password)
    const header = await encryption.encHead(keys[0], [keys[1]], ed)
    console.log(header[0])
    const chunksize = 65536
    let counter = 0
    let offset = 0
    while (offset < file3.files[0].size) {
      counter++
      const chunkfile = await file3.files[0].slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      const encryptedtext = await encryption.encryption(header, new Uint8Array(chunk), counter, block)
      // const encoder = new TextEncoder()
      if (encryptedtext) {
        console.log(encryptedtext)
        // console.log(encoder.encode(encryptedtext))
      }

      offset += chunksize
    }
    console.log('all done')
  })()
}

document.getElementById('button2').onclick = function () { Decryption() }

function Decryption () {
  /*
  const fileInput = document.getElementById('input')
  const seckeyFile2 = await fileInput.files[0].text()
  const file = document.getElementById('input4')
  console.log(file)
  const file2 = document.getElementById('input5')
  console.log(file2)
  const password = document.getElementById('psw3').value
  console.log(password);
  (async () => {
    const seckeyFile = await file.files[0].text()
    const keys = await keyfiles.encryption_keyfiles([seckeyFile], password)
    const headerChunk = await file2.files[0].slice(0, 1000)
    const chunkHeader = await headerChunk.arrayBuffer()
    const header = await decryption.header_deconstruction(new Uint8Array(chunkHeader), keys[0])
    const chunksize = 65564
    let counter = 0
    let offset = header[4]
    while (offset < file2.files[0].size) {
      counter++
      const chunkfile = await file2.files[0].slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      const plaintext = await decryption.decrypption(header, new Uint8Array(chunk), counter)
      const decoder = new TextDecoder()
      if (plaintext) {
        console.log(decoder.decode(plaintext))
      }
      offset += chunksize
    }
    console.log('all done')
  })()
}

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
