const helperfunction = require('./helper functions.js')
const generateKeyPair = require('@stablelib/x25519')
const scrypt = require('scrypt-js')
const keygen = require('./keygen.js')
const _sodium = require('libsodium-wrappers')

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
  console.log(seckey)
  try {
    let a = ''
    await (async () => {
      await _sodium.ready
      const sodium = _sodium
      if (passphrase) {
        const salt = sodium.randombytes_buf(16)
        const saltround = new Uint8Array(4 + salt.length)
        saltround.set([0, 0, 0, 0])
        saltround.set(salt, 4)
        const N = 16384; const r = 8; const p = 1
        const dklen = 32
        const keyPrmoise = scrypt.scrypt(helperfunction.string2byte(passphrase), salt, N, r, p, dklen)
        const key = keyPrmoise.then(function (result) {
          const nonce = sodium.randombytes_buf(12)
          const decData = _sodium.crypto_aead_chacha20poly1305_ietf_encrypt(seckey, null, null, nonce, result)
          const decNonce = Buffer.concat([magicBytestring, kdfScript, saltround, chiperChacha, nonce, decData])
          const x = new Uint8Array(decNonce)
          const b64 = btoa(String.fromCharCode.apply(null, x))
          return '-----BEGIN CRYPT4GH PRIVATE KEY-----\n' + b64 + '\n-----END CRYPT4GH PRIVATE KEY-----\n'
        })
        a = await key
      } else {
        const decNonce = Buffer.concat([magicBytestring, kdfNoneBestring, chiperNoneBytestring, seckey])
        const x = new Uint8Array(decNonce)
        const b64 = btoa(String.fromCharCode.apply(null, x))
        a = '-----BEGIN CRYPT4GH PRIVATE KEY-----\n' + b64 + '\n-----END CRYPT4GH PRIVATE KEY-----\n'
      }
    })()
    return a
  } catch (e) {
    console.trace('Secret key generation not possible.')
  }
}
