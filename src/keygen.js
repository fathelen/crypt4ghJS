import * as helperfunction from './helper functions.js'
import * as generateKeyPair from '@stablelib/x25519'
import scrypt from 'scrypt-js'
import _sodium from 'libsodium-wrappers'
import { Buffer } from 'buffer'
// const helperfunction = require('./helper functions.js')
// const generateKeyPair = require('@stablelib/x25519')
// const scrypt = require('scrypt-js')
// const keygen = require('./keygen.js')
// const _sodium = require('libsodium-wrappers')
// const Buffer = require('buffer/').Buffer

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
export async function keygen (pasphrase) {
  try {
    console.log('hallo')
    const keys = generateKeyPair.generateKeyPair()
    console.log('1: ', keys)
    const pubkeyFile = createPubkey(keys.publicKey)
    console.log('2: ', pubkeyFile)
    const seckeyFile = await createSeckey(keys.secretKey, pasphrase)
    console.log('3: ', seckeyFile)
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
export function createPubkey (pubkey) {
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
export async function createSeckey (seckey, passphrase) {
  try {
    console.log('a')
    let a = ''
    await (async () => {
      console.log('b')
      await _sodium.ready
      const sodium = _sodium
      console.log('c')
      if (passphrase) {
        console.log('c2')
        if (passphrase.replace(/\s+/g, '') === '') {
          console.log('hier gelanded')
          throw new Error('Password can not be empty string')
        }
        console.log('d')
        const salt = sodium.randombytes_buf(16)
        console.log('e')
        const saltround = new Uint8Array(4 + salt.length)
        console.log('f')
        saltround.set([0, 0, 0, 0])
        saltround.set(salt, 4)
        const N = 16384; const r = 8; const p = 1
        const dklen = 32
        console.log('g')
        const keyPrmoise = scrypt.scrypt(helperfunction.string2byte(passphrase), salt, N, r, p, dklen)
        console.log('h')
        const key = keyPrmoise.then(function (result) {
          console.log('i')
          const nonce = sodium.randombytes_buf(12)
          console.log('j')
          const decData = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(seckey, null, null, nonce, result)
          console.log('bis hier')
          const decNonce = Buffer.concat([magicBytestring, new Uint8Array([0, 6]), kdfScript, new Uint8Array([0, 20]), saltround, new Uint8Array([0, 17]), chiperChacha, new Uint8Array([0, 12 + decData.length]), nonce, decData])
          const x = new Uint8Array(decNonce)
          const b64 = btoa(String.fromCharCode.apply(null, x))
          console.log('3')
          return '-----BEGIN CRYPT4GH PRIVATE KEY-----\n' + b64 + '\n-----END CRYPT4GH PRIVATE KEY-----\n'
        })
        a = await key
      } else {
        console.log('iii')
        const decNonce = Buffer.concat([magicBytestring, new Uint8Array([0, 4]), kdfNoneBestring, new Uint8Array([0, 4]), chiperNoneBytestring, new Uint8Array([0, 32]), seckey])
        console.log('buffer nicht schuld')
        const x = new Uint8Array(decNonce)
        console.log('xxx')
        const b64 = btoa(String.fromCharCode.apply(null, x))
        console.log('fetrig')
        a = '-----BEGIN CRYPT4GH PRIVATE KEY-----\n' + b64 + '\n-----END CRYPT4GH PRIVATE KEY-----\n'
      }
    })()
    return a
  } catch (e) {
    console.trace('Secret key generation not possible.')
    throw new Error('Password can not be empty string')
  }
}
