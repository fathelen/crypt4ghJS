
import * as crypt4GHJS from 'crypt4gh_js'
import { Buffer } from 'buffer'


const acc = document.getElementsByClassName('accordion')
let i

for (i = 0; i < acc.length; i++) {
  acc[i].addEventListener('click', function () {
    this.classList.toggle('active')
    const panel = this.nextElementSibling
    if (panel.style.display === 'block') {
      panel.style.display = 'none'
    } else {
      panel.style.display = 'block'
    }
  })
}

// KeyGen
async function keyfile () {
  const password = await document.getElementById('psw').value
  const result = await crypt4GHJS.keygen.keygen(password)
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
  const enteredText = await document.getElementById('w3review').value
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
  // const pubkeyFile = await file2.files[0].text()
  const pubkeyFiles = await file2.files
  let pubs = []
  for(let i=0; i<pubkeyFiles.length; i++){
   let pub = await pubkeyFiles[i].text()
   pubs.push(pub)
  }
  pubs.unshift(seckeyFile)
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles(pubs, password)
  let sec = keys.shift()
  let pub = keys
  const header = await crypt4GHJS.encryption.encHead(sec, pub, ed, block)
  c4ghtext.push(header[0])
  const chunksize = 65536
  let counter = 0
  let offset = 0
  if (enteredText !== '') {
    while (offset < enteredText.length) {
      counter++
      const chunkfile = await enteredText.slice(offset, offset + chunksize)
      const encryptedtext = await crypt4GHJS.encryption.encryption(header, Uint8Array.from(chunkfile.split('').map(x => x.charCodeAt())), counter, block)
      if (encryptedtext) {
        c4ghtext.push(encryptedtext)
      }

      offset += chunksize
    }
  } else {
    while (offset < file3.files[0].size) {
      counter++
      const chunkfile = await file3.files[0].slice(offset, offset + chunksize)
      const chunk = await chunkfile.arrayBuffer()
      const encryptedtext = await crypt4GHJS.encryption.encryption(header, new Uint8Array(chunk), counter, block)
      if (encryptedtext) {
      // yield encryptedtext
        c4ghtext.push(encryptedtext)
      }

      offset += chunksize
    }
  }
  console.log('all done')
  const buffered = Buffer.concat(c4ghtext)
  const text = new Uint8Array(buffered)
  return text
}

async function * decr () {
  let decText = ''
  const file = document.getElementById('input4')
  const file2 = document.getElementById('input5')
  let password = document.getElementById('psw3').value
  if (password === '') {
    password = undefined
  }
  const seckeyFile = await file.files[0].text()
  const keys = await crypt4GHJS.keyfiles.encryptionKeyfiles([seckeyFile], password)
  const headerChunk = await file2.files[0].slice(0, 1000)
  const chunkHeader = await headerChunk.arrayBuffer()
  const header = await crypt4GHJS.decryption.headerDeconstruction(new Uint8Array(chunkHeader), keys[0])
  const chunksize = 65564
  let counter = 0
  let offset = header[4]
  while (offset < file2.files[0].size) {
    counter++
    const chunkfile = await file2.files[0].slice(offset, offset + chunksize)
    const chunk = await chunkfile.arrayBuffer()
    const plaintext = await crypt4GHJS.decryption.decrypption(header, new Uint8Array(chunk), counter)
    const decoder = new TextDecoder()
    if (plaintext) {
      decText += plaintext
      /** 
      decText += decoder.decode(plaintext)
      console.log('Länge plain: ', plaintext.length)
      console.log('längedec: ', decText.length) */
      yield decText
    }
    offset += chunksize
  }
  console.log('all done')
}
// Download keyfiles
document.getElementById('btn').addEventListener('click', async function () {
  const keys = await keyfile()
  const text = keys[0]
  const secName = await document.getElementById('secname').value
  let filename = 'secret_keyfile.sec'
  if (secName !== '') {
    filename = secName
  }
  download(filename, text)
  const keyPreview = document.getElementById('filecontents')
  keyPreview.innerText += keys
  const text2 = keys[1]
  const pubName = await document.getElementById('pubname').value
  let filename2 = 'public_keyfile.pub'
  if (pubName !== '') {
    filename2 = pubName
  }

  download(filename2, text2)
}, false)

// Download c4gh file
document.getElementById('but').addEventListener('click', async function () {
  const enc = await encr()
  let filename = 'c4gh_file.c4gh'
  const c4ghName = await document.getElementById('c4ghname').value
  if (c4ghName !== '') {
    filename = c4ghName
  }
  saveByteArray([enc], filename)
  const keyPreview = document.getElementById('enccontents')
  keyPreview.innerText += enc.subarray(0, 500)
}, false)

// Download decrypted file
document.getElementById('but2').addEventListener('click', async function () {
  const dec = decr()
  let filename = 'decrypted_file'
  const decName = await document.getElementById('decname').value
  if (decName !== '') {
    filename = decName
  }
  const element = document.createElement('a')
  let next
  let index = 0
  while (!(next = await dec.next()).done) {
    const chunk = next.value
    if (index === 0) {
      const keyPreview = document.getElementById('deccontents')
      keyPreview.innerText += chunk.substring(0, 500)
    }
    index++
    element.setAttribute('href',
      'data:text/plain;charset=utf-8,' +
        encodeURIComponent(chunk))
  }
  element.setAttribute('download', filename)
  document.body.appendChild(element)
  element.click()

  document.body.removeChild(element)

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
