const helperfunction = require('./helper functions')
const generateKeyPair = require('@stablelib/x25519')
const ChaCha20Poly1305 = require('@stablelib/chacha20poly1305')
const scrypt = require('scrypt-js')
const keygen = require('./keygen.js')

const magicBytestring = helperfunction.string2byte('c4gh-v1')
// without passphrase
const kdfNoneBestring = helperfunction.string2byte('none')
const chiperNoneBytestring = helperfunction.string2byte('none')
// with pasphrase
const kdfScript = helperfunction.string2byte('scrypt')
const chiperChacha = helperfunction.string2byte('chacha20_poly1305')

/**
 * Main function for key generation
 * @param {*} pasphrase => optional parameter, password (string)
 * @returns => List of secret key content and public key content
 */
exports.keygen = async function (pasphrase) {
  try {
    const keys = generateKeyPair.generateKeyPair()
    const pubkeyFile = keygen.create_pubkey(keys.publicKey)
    const seckeyFile = await keygen.create_seckey(keys.secretKey, pasphrase)
    return [seckeyFile, pubkeyFile]
  } catch (e) {
    console.trace('Key generation not possible.')
  }
}

/**
 * Function to create public key contents
 * @param {*} pubkey => public key (Uint8array of length 32)
 * @returns => pubkey content as string
 */
exports.create_pubkey = function (pubkey) {
  try {
    const b64 = btoa(String.fromCharCode.apply(null, pubkey))
    return '-----BEGIN CRYPT4GH PUBLIC KEY-----\n' + b64 + '\n-----END CRYPT4GH PUBLIC KEY-----\n'
  } catch (e) {
    console.trace('Pubkey generation not possible.')
  }
}

/**
 * Function to create secret key contents
 * @param {*} seckey => secret key (Uint8array of length 32)
 * @param {*} passphrase => optional parameter, string to encrypt secret key
 * @returns => seckey content as string
 */
exports.create_seckey = async function (seckey, passphrase) {
  try {
    if (passphrase !== '') {
      const salt = helperfunction.randomBytes(16)
      const saltround = new Uint8Array(4 + salt.length)
      saltround.set([0, 0, 0, 0])
      saltround.set(salt, 4)
      const N = 16384; const r = 8; const p = 1
      const dklen = 32
      const keyPrmoise = scrypt.scrypt(helperfunction.string2byte(passphrase), salt, N, r, p, dklen)
      const key = keyPrmoise.then(function (result) {
        const nonce = helperfunction.randomBytes(12)
        const chacha20poly1305 = new ChaCha20Poly1305.ChaCha20Poly1305(result)
        const sealedHeader = chacha20poly1305.seal(nonce, seckey)
        const fullUint8 = new Uint8Array(magicBytestring.length + kdfScript.length + chiperChacha.length + sealedHeader.length + 8 + nonce.length + saltround.length)
        fullUint8.set(magicBytestring)
        fullUint8.set([0, 6], magicBytestring.length)
        fullUint8.set(kdfScript, magicBytestring.length + 2)
        fullUint8.set([0, 20], magicBytestring.length + kdfScript.length + 2)
        fullUint8.set(saltround, magicBytestring.length + kdfScript.length + 4)
        fullUint8.set([0, 17], magicBytestring.length + kdfScript.length + saltround.length + 4)
        fullUint8.set(chiperChacha, magicBytestring.length + kdfScript.length + saltround.length + 6)
        fullUint8.set([0, 12 + sealedHeader.length], magicBytestring.length + kdfScript.length + chiperChacha.length + saltround.length + 6)
        fullUint8.set(nonce, magicBytestring.length + kdfScript.length + chiperChacha.length + saltround.length + 8)
        fullUint8.set(sealedHeader, magicBytestring.length + kdfScript.length + chiperChacha.length + nonce.length + saltround.length + 8)
        const b64 = btoa(String.fromCharCode.apply(null, fullUint8))
        return '-----BEGIN CRYPT4GH PRIVATE KEY-----\n' + b64 + '\n-----END CRYPT4GH PRIVATE KEY-----\n'
      })
      const a = await key
      return a
    } else {
      const fullUint8 = new Uint8Array(magicBytestring.length + kdfNoneBestring.length + chiperNoneBytestring.length + seckey.length + 6)
      fullUint8.set(magicBytestring)
      fullUint8.set([0, 4], magicBytestring.length)
      fullUint8.set(kdfNoneBestring, magicBytestring.length + 2)
      fullUint8.set([0, 4], magicBytestring.length + kdfNoneBestring.length + 2)
      fullUint8.set(chiperNoneBytestring, magicBytestring.length + kdfNoneBestring.length + 4)
      fullUint8.set([0, 32], magicBytestring.length + kdfNoneBestring.length + chiperNoneBytestring.length + 4)
      fullUint8.set(seckey, magicBytestring.length + kdfNoneBestring.length + chiperNoneBytestring.length + 6)
      const b64 = btoa(String.fromCharCode.apply(null, fullUint8))
      return '-----BEGIN CRYPT4GH PRIVATE KEY-----\n' + b64 + '\n-----END CRYPT4GH PRIVATE KEY-----\n'
    }
  } catch (e) {
    console.trace('Secret key generation not possible.')
  }
}
