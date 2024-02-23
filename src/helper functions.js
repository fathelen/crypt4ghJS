/**
 * Function to compute byte representation from string
 * @param {*} str =>input string
 * @returns => string in byte representation
 */
export function string2byte (str) {
  try {
    const result = new Uint8Array(str.length)
    for (let i = 0; i < str.length; i++) {
      result[i] = str.charCodeAt(i)
    }
    return result
  } catch (e) {
    console.trace('conversion not possible')
  }
}

/**
   * Function to compare Int8Arrays
   * @param {*} buf1 => first buffer to  compare
   * @param {*} buf2 => second buffer to compare
   * @returns true if buf1 and buf2 are equal
   */
export function equal (buf1, buf2) {
  try {
    if (buf1.byteLength !== buf2.byteLength) return false
    const dv1 = new Int8Array(buf1)
    const dv2 = new Int8Array(buf2)
    for (let i = 0; i !== buf1.byteLength; i++) {
      if (dv1[i] !== dv2[i]) return false
    }
    return true
  } catch (e) {
    console.trace('comparing not possible.')
  }
}

/**
 * Function to compute base64 to ArrayBuffer
 * @param {*} base64 => input string
 * @returns => Uint8array
 */
export function base64ToArrayBuffer (base64) {
  try {
    const binaryString = atob(base64)
    const bytes = new Uint8Array(binaryString.length)
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i)
    }
    return bytes
  } catch (e) {
    console.trace('conversion not possible.')
  }
}

export function random (length) {
  let result = ''
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  const charactersLength = characters.length
  let counter = 0
  while (counter < length) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength))
    counter += 1
  }
  return result
}

export default { random, base64ToArrayBuffer, equal, string2byte }
