const helperfunction = require('./helper functions')
// const crypto = require('crypto')
const scrypt = require('scrypt-js')
const sodium = require('libsodium-wrappers')

const magicBytestring = helperfunction.string2byte('c4gh-v1')
const kdfNoneBytestring = helperfunction.string2byte('none')
const kdfScript = helperfunction.string2byte('scrypt')
const chiperNoneBytestring = helperfunction.string2byte('none')
const chiperChacha = helperfunction.string2byte('chacha20_poly1305')
const seckeyStart = '-----BEGIN CRYPT4GH PRIVATE KEY-----'
const seckeyEnd = '-----END CRYPT4GH PRIVATE KEY-----'
const pubkeyStart = '-----BEGIN CRYPT4GH PUBLIC KEY-----'
const pubkeyEnd = '-----END CRYPT4GH PUBLIC KEY-----'

/**
 * Function to check if given seckey and/or pubkeyfiles are in crypt4gh format.
 * Additionally decrypts the key, if the seckey/pubkey file is password protected
 * @param {*} keys => List containing keys in Uint8Array format
 * @param {*} password => optional parameter, to decrypt password protected
 *                         secret keys
 * @returns => list of 32byte keys, starting with the seckret key, pubkeys second
 */
exports.encryption_keyfiles = async (keys, password = '') => {
  console.log('seckey in enc: ', keys)
  const solvedKeys = []
  try {
    for (let i = 0; i < keys.length; i++) {
      let seckey = new Uint8Array(32)
      let pubkey = new Uint8Array(32)
      const wordWrap1 = keys[i].indexOf('\n')
      console.log('1')
      const wordWrap2 = keys[i].indexOf('\n', wordWrap1 + 1)
      const wordWrap3 = keys[i].indexOf('\n', wordWrap2 + 1)
      const row1 = keys[i].substring(0, wordWrap1)
      console.log('2')
      const row2 = keys[i].substring(wordWrap1 + 1, wordWrap2)
      const row3 = keys[i].substring(wordWrap2 + 1, wordWrap3)
      const row2Array = helperfunction.base64ToArrayBuffer(row2)
      console.log(row1)
      if (row1 === seckeyStart && row3 === seckeyEnd) {
        seckey = await secret(row2Array, seckey, password)
        solvedKeys.push(seckey)
      } else if (row1 === pubkeyStart && row3 === pubkeyEnd) {
        const keyPub = keys[i].substring(36, 80)
        pubkey = helperfunction.base64ToArrayBuffer(keyPub)
        solvedKeys.push(pubkey)
      } else {
        console.trace('Not a crypt4gh keyfile!')
      }
    }
    return solvedKeys
  } catch (e) {
    console.trace("Keyfiles couldn't be decrypted!")
  }
}

/**
 * Function to decrypt the secret key
 * @param {*} keyContent => encrypted key content
 * @param {*} seckey => Uint8array for seckey
 * @returns => secret key (Uint8array 32 bytes)
 */
async function secret (keyContent, seckey, password) {
  console.log('secret und password: ', keyContent, '  ', password)
  try {
    console.log('3')
    console.log(keyContent.subarray(0, 7), '   ', keyContent.subarray(9, 15))
    if (helperfunction.equal(keyContent.subarray(0, 7), magicBytestring)) {
      console.log('8')
      if (helperfunction.equal(keyContent.subarray(9, 13), kdfNoneBytestring)) {
        if (helperfunction.equal(keyContent.subarray(15, 19), chiperNoneBytestring)) {
          seckey = keyContent.subarray(21)
          return seckey
        }
      } else if (helperfunction.equal(keyContent.subarray(9, 15), kdfScript)) {
        console.log('4')
        const kdfoptions = keyContent.subarray(17, 37)
        const salt = kdfoptions.subarray(4)
        if (helperfunction.equal(keyContent.subarray(39, 56), chiperChacha)) {
          const N = 16384; const r = 8; const p = 1
          const dklen = 32
          const keyPrmoise = scrypt.scrypt(helperfunction.string2byte(password), salt, N, r, p, dklen)
          const key = keyPrmoise.then(async function (result) {
            const sharedkey = result
            const nonce = keyContent.subarray(58, 70)
            const encData = keyContent.subarray(70)
            console.log(nonce)
            const encKey = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, encData, null, nonce, sharedkey)
            console.log('enc: ', encKey)
            return encKey

            /*
            const algorithm = 'chacha20-poly1305'
            const cipher = crypto.createCipheriv(algorithm, sharedkey, nonce)
            console.log('cipher: ', cipher)
            const encryptedResult = cipher.update(encData)
            console.log('encres: ', encryptedResult)
            const x = new Uint8Array(encryptedResult.subarray(0, 32))
            console.log('x: ', x)
            return x */
          })
          return await key
        }
      } else {
        console.trace('Wrong encryption method')
      }
    }
  } catch (e) {
    console.trace(e)
  }
}
