const index = require('crypt4gh_js')
const fs = require('fs')
const testDataUnencrypted = fs.readFileSync('../testData/abcd.txt', 'utf8')


// Keyfiles
// keyfiles without password
const pubkey = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nGER04WfJXzPHiCWe94CHlMY6sp6zwWpAehA0MMHjdVQ=\n-----END CRYPT4GH PUBLIC KEY-----\n'
const seckey = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAEbm9uZQAEbm9uZQAg4BW6LpwKHBQN0MCZgjPtDafcGbN5wRmUSrIwEcN4te0=\n-----END CRYPT4GH PRIVATE KEY-----\n'

// kefiles with password (example password = password)
// const pubkeyPass = '-----BEGIN CRYPT4GH PUBLIC KEY-----\nvHrVpBpFLpX/OquK2Ze4Mfzb8aVrn05XmTgT4ymVwzE=\n-----END CRYPT4GH PUBLIC KEY-----\n'
// const seckeyPass = '-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAMHZyZm0wb3JrM2E5d2QyeQARY2hhY2hhMjBfcG9seTEzMDUAPHUyY2lhbDQ1dWZydxzqFWikrPHQc6dKqWySS59BoMAe1L0FRmBXnwPd80N4fJBJS5f+vnmlA+JZ8qCpow==\n-----END CRYPT4GH PRIVATE KEY-----\n'
// Example text for encryption
const unencryptedText = Buffer.from('abcdefghijklmnopqrstuvwxyz');

(async () => {
/// ////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Example Key generation
// with password
  try {
    const keyfiles = index.keygen.keygen('password')
    console.log(await keyfiles)
  } catch (e) {
    console.trace('Could not generate new keyfiles')
  }
  // without password
  try {
    const keyfiles = index.keygen.keygen('')
    console.log(await keyfiles)
  } catch (e) {
    console.trace('Could not generate new keyfiles')
  }
  /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Example check keyfiles and encrypt data
  // without password
  try {
    const keys = await index.keyfiles.encryption_keyfiles([seckey, pubkey])
    // const keys2 = await index.keyfiles.encryption_keyfiles([seckeyPass, pubkeyPass], 'gunpass')
    /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Example Encryption
    const edit = null
    const block = null
    // simple Encryption without editlist or blocks
    try {
      // const encryptedText = await index.encryption.encryption(unencryptedText, keys[0], [keys[1]], block, edit)
      async function generate () {
        for await (const val of index.encryption.encryption(Buffer.from(testDataUnencrypted), keys[0], [keys[1]], block, edit)) {
          console.log(val)
        }
      }

      generate()
      /*
      // check file format and encryptability
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const checkSimple = await index.check_fileformat.check(mergedArray(encryptedText), keys[0])
        console.log(checkSimple)
      } catch (e) {
        console.trace('File format could not be checked')
      }
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption without blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      let blocks = null
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedText), keys[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption with blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      blocks = [1]
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedText), keys[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Reeencryption
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const reeencryptText = await index.reeencryption.reencrypt(mergedArray(encryptedText), [keys[1]], keys[0])
        console.log(mergedArray(reeencryptText))
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        let blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be reeencrypted')
      }
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Rearangement
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // single edit list
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const editlist = [0, 9]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedText), keys[0], [keys[1]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // let blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // multiple edit lists
      try {
        const editlist = [[0, 2], [0, 9]]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedText), keys[0], [keys[1], keys[0]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      } */
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    } catch (e) {
      console.trace('Data could not be encrypted!')
    }
    /*
    // Encryption with single editlist
    edit = [0, 10]
    try {
      const encryptedtextEdit = await index.encryption.encryption(unencryptedText, keys[0], [keys[1]], block, edit)
      console.log(encryptedtextEdit)
      // check file format and encryptability
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const checkEdit = await index.check_fileformat.check(mergedArray(encryptedtextEdit), keys[0])
        console.log(checkEdit)
      } catch (e) {
        console.trace('File format could not be checked')
      }
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption without blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      const blocks = null
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextEdit), keys[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption with blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      /*
      blocks = [1]
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextEdit), keys[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Reeencryption
      try {
        const reeencryptText = await index.reeencryption.reencrypt(mergedArray(encryptedtextEdit), [keys[1]], keys[0])
        console.log(mergedArray(reeencryptText))
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // let blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Coud not be reeencrypted')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Rearangement
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // single edit list
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const editlist = [0, 9]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextEdit), keys[0], [keys[1]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // multiple edit lists
      try {
        const editlist = [[0, 2], [0, 9]]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextEdit), keys[0], [keys[1], keys[0]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    } catch (e) {
      console.trace('Data could not be encrypted!')
    }
    // Encryption with multiple editlists
    edit = [[0, 10], [0, 5]]
    try {
      const encryptedtextMultedit = await index.encryption.encryption(unencryptedText, keys[0], [keys[1], keys[1]], block, edit)
      console.log(encryptedtextMultedit)
      // check file format and encryptability
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const checkMultiedit = await index.check_fileformat.check(mergedArray(encryptedtextMultedit), keys[0])
        console.log(checkMultiedit)
      } catch (e) {
        console.trace('File format could not be checked')
      }
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption without blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      const blocks = null
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextMultedit), keys[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption with blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      /*
      blocks = [1]
      try {
        const plaintext = await index.decryption.decryption(encryptedtextMultedit, keys[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Reeencryption
      try {
        const reeencryptText = await index.reeencryption.reencrypt(mergedArray(encryptedtextMultedit), [keys[1]], keys[0])
        console.log(mergedArray(reeencryptText))
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Coud not be reeencrypted')
      }
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Rearangement
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // single edit list
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const editlist = [0, 9]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextMultedit), keys[0], [keys[1]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // multiple edit lists
      try {
        const editlist = [[0, 2], [0, 9]]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextMultedit), keys[0], [keys[1], keys[0]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    } catch (e) {
      console.trace('Data could not be encrypted!')
    }
    /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Encryption with Blocks
    /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    block = [1]
    edit = null
    try {
      const encryptedtextBlocks = await index.encryption.encryption(unencryptedText, keys[0], [keys[1], keys[1]], block, edit)
      console.log(encryptedtextBlocks)
      // check file format and encryptability
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const checkBlock = await index.check_fileformat.check(mergedArray(encryptedtextBlocks), keys[0])
        console.log(checkBlock)
      } catch (e) {
        console.trace('File format could not be checked')
      }
      // Decryption without blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      let blocks = null
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextBlocks), keys[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption with blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      blocks = [1]
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextBlocks), keys[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext))) // sollte nicht funktionieren exception schreiben
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Reeencryption
      try {
        const reeencryptText = await index.reeencryption.reencrypt(mergedArray(encryptedtextBlocks), [keys[1]], keys[0])
        console.log(mergedArray(reeencryptText))
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        let blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Coud not be reeencrypted')
      }
      // Rearangement
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // single edit list
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const editlist = [0, 9]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextBlocks), keys[0], [keys[1]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // multiple edit lists
      try {
        const editlist = [[0, 2], [0, 9]]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextBlocks), keys[0], [keys[1], keys[0]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keys[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    } catch (e) {
      console.trace('Data could not be encrypted!')
    } */
    /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  } catch (e) {
    console.trace('There is a problem with the key data!')
  }
  /*
  // with password
  try {
    const keysPassword = await index.keyfiles.encryption_keyfiles([seckeyPass, pubkeyPass], 'gunpass')
    console.log(keysPassword)
    /// /////////////////////////////////////////////////////////////////////////////////////////////////
    // Example Encryption
    let edit
    let block = null
    // simple Encryption without editlist or blocks
    try {
      const encryptedtext = await index.encryption.encryption(unencryptedText, keysPassword[0], [keysPassword[1]], block, edit)
      console.log(encryptedtext)
      // check file format and encryptability
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const checkSimple = await index.check_fileformat.check(mergedArray(encryptedtext), keysPassword[0])
        console.log(checkSimple)
      } catch (e) {
        console.trace('File format could not be checked')
      }
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption without blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      let blocks = null
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtext), keysPassword[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption with blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      blocks = [1]
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtext), keysPassword[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Reeencryption
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const reeencryptText = await index.reeencryption.reencrypt(mergedArray(encryptedtext), [keysPassword[1]], keysPassword[0])
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        let blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        // ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Coud not be reeencrypted')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Rearangement
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // single edit list
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const editlist = [0, 9]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtext), keysPassword[0], [keysPassword[1]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // multiple edit lists
      try {
        const editlist = [[0, 2], [0, 9]]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtext), keysPassword[0], [keysPassword[1], keysPassword[0]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    } catch (e) {
      console.trace('Data could not be encrypted!')
    }
    // Encryption with single editlist
    edit = [0, 10]
    try {
      const encryptedtextEdit = await index.encryption.encryption(unencryptedText, keysPassword[0], [keysPassword[1]], block, edit)
      console.log(encryptedtextEdit)
      // check file format and encryptability
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const checkEdit = await index.check_fileformat.check(mergedArray(encryptedtextEdit), keysPassword[0])
        console.log(checkEdit)
      } catch (e) {
        console.trace('File format could not be checked')
      }
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption without blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      const blocks = null
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextEdit), keysPassword[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption with blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      /*
      blocks = [1]
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextEdit), keysPassword[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')// Hier richtig
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Reeencryption
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const reeencryptText = await index.reeencryption.reencrypt(mergedArray(encryptedtextEdit), [keysPassword[1]], keysPassword[0])
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Coud not be reeencrypted')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Rearangement
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // single edit list
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const editlist = [0, 9]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextEdit), keysPassword[0], [keysPassword[1]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // multiple edit lists
      try {
        const editlist = [[0, 2], [0, 9]]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextEdit), keysPassword[0], [keysPassword[1], keysPassword[0]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace("Couldn't be rearranged")
      }
    /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    } catch (e) {
      console.trace('Data could not be encrypted!')
    }
    // Encryption with multiple editlists
    edit = [[0, 10], [0, 5]]
    try {
      const encryptedtextMultedit = await index.encryption.encryption(unencryptedText, keysPassword[0], [keysPassword[1], keysPassword[1]], block, edit)
      console.log(encryptedtextMultedit)
      // check file format and encryptability
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const checkMultiedit = await index.check_fileformat.check(mergedArray(encryptedtextMultedit), keysPassword[0])
        console.log(checkMultiedit)
      } catch (e) {
        console.trace("File format could't be checked")
      }
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption without blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      const blocks = null
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextMultedit), keysPassword[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption with blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      /*
      blocks = [1]
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextMultedit), keysPassword[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!') // Hier richtig
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Reeencryption
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const reeencryptText = await index.reeencryption.reencrypt(mergedArray(encryptedtextMultedit), [keysPassword[1]], keysPassword[0])
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Coud not be reeencrypted')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Rearangement
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // single edit list
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const editlist = [0, 9]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextMultedit), keysPassword[0], [keysPassword[1]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // multiple edit lists
      try {
        const editlist = [[0, 2], [0, 9]]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextMultedit), keysPassword[0], [keysPassword[1], keysPassword[0]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    } catch (e) {
      console.trace('Data could not be encrypted!')
    }
    // Encryption with Blocks
    block = [1]
    edit = null
    try {
      const encryptedtextBlocks = await index.encryption.encryption(unencryptedText, keysPassword[0], [keysPassword[1], keysPassword[1]], block, edit)
      console.log(encryptedtextBlocks)
      // check file format and encryptability
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const checkBlock = await index.check_fileformat.check(mergedArray(encryptedtextBlocks), keysPassword[0])
        console.log(checkBlock)
      } catch (e) {
        console.trace('File format could not be checked')
      }
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption without blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      let blocks = null
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextBlocks), keysPassword[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Decryption with blocks
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
      blocks = [1]
      try {
        const plaintext = await index.decryption.decryption(mergedArray(encryptedtextBlocks), keysPassword[0], blocks)
        const textdecoder = new TextDecoder()
        console.log(textdecoder.decode(mergedArray(plaintext)))
      } catch (e) {
        console.trace('Decryption impossible!') // Hier richtig
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Reeencryption
      /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const reeencryptText = await index.reeencryption.reencrypt(mergedArray(encryptedtextBlocks), [keysPassword[1]], keysPassword[0])
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        let blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(reeencryptText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Coud not be reeencrypted')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // Rearangement
      /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // single edit list
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      try {
        const editlist = [0, 9]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextBlocks), keysPassword[0], [keysPassword[1]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      // multiple edit lists
      try {
        const editlist = [[0, 2], [0, 9]]
        const rearrangedText = await index.rearrangment.rearrange(mergedArray(encryptedtextBlocks), keysPassword[0], [keysPassword[1], keysPassword[0]], editlist)
        console.log(rearrangedText)
        // Decryption without blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        const blocks = null
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!')
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption with blocks
        /// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        blocks = [1]
        try {
          const plaintext = await index.decryption.decryption(mergedArray(rearrangedText), keysPassword[0], blocks)
          const textdecoder = new TextDecoder()
          console.log(textdecoder.decode(mergedArray(plaintext)))
        } catch (e) {
          console.trace('Decryption impossible!') // here error!
        }
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
      } catch (e) {
        console.trace('Could not be rearranged')
      }
      /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    } catch (e) {
      console.trace('Data could not be encrypted!')
    }
  } catch (e) {
    console.trace('Could not decrypt keyfiles')
  } */
})()

/*
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
} */
