# Crypt4GH-JS: Needed changes to implement Crypt4GH for web enviroments
To implement CRypt4GH-JS two major changes had to be developed, first the streaming of files and second the recalculation of the edit list according to the streamed chunks.

## Stream based approach 
To minimize the web storage and enable the users to upload
huge data files to web-based data management systems, we
decided to use a stream based approach. Uploaded files are
streamed in chunks of 65 536byte, as the given chunk size in
the GA4GH File Encryption Standard. The header and the
individual chunks are encrypted separately on the client-site
and can then be send, already encrypted, to the server.
For the decryption we used the same concept, encrypted chunks
of 65 564byte byte are streamed and decrypted separately on
the client-site. The expand of 28byte byte from plaintext to
encrypted text is due to the nonce and message authentication
code (MAC) used for chacha20-ietf-poly1305.

## Transformation of edit lists
Since the streamed chunks are decrypted individually, the editlist has to be recalculated to know, which chunks have to be fully or partly decrypted. 
We implemented this process in two steps.
<br> 
<br> 
First step is to differentiate, if a chunk has to be decrypted and if so, if the chunk has to be fully or partly decrypted : 
```

export function applyEditlist (edlist, decryptedText) {
  try {
    const editedData = []
    let pos = BigInt(0)
    const len = BigInt(decryptedText.length)
    for (let i = 0; i < edlist.length; i = i + 2) {
      const discard = edlist[i]
      pos = pos + discard
      if (i === edlist.length - 1) {
        const part = decryptedText.subarray(Number(pos), Number(len))
        editedData.push(part)
      } else {
        const keep = edlist[i + 1]
        const part = decryptedText.subarray(Number(pos), Number(pos) + Number(keep))
        editedData.push(part)
        pos = pos + keep
      }
    }
    let length = 0
    editedData.forEach(item => {
      length += item.length
    })
    // Create a new array with total length and merge all source arrays.
    const mergedArray = new Uint8Array(length)
    let offset = 0
    editedData.forEach(item => {
      mergedArray.set(item, offset)
      offset += item.length
    })
    return mergedArray
  } catch (e) {
    console.trace('edit list could not be applied.')
  }
}

```
Second step is two recalculate the needed part of the chunk, if the chunk has to be partly decrypted:
```

export function applyEditlist (edlist, decryptedText) {
  try {
    const editedData = []
    let pos = BigInt(0)
    const len = BigInt(decryptedText.length)
    for (let i = 0; i < edlist.length; i = i + 2) {
      const discard = edlist[i]
      pos = pos + discard
      if (i === edlist.length - 1) {
        const part = decryptedText.subarray(Number(pos), Number(len))
        editedData.push(part)
      } else {
        const keep = edlist[i + 1]
        const part = decryptedText.subarray(Number(pos), Number(pos) + Number(keep))
        editedData.push(part)
        pos = pos + keep
      }
    }
    let length = 0
    editedData.forEach(item => {
      length += item.length
    })
    // Create a new array with total length and merge all source arrays.
    const mergedArray = new Uint8Array(length)
    let offset = 0
    editedData.forEach(item => {
      mergedArray.set(item, offset)
      offset += item.length
    })
    return mergedArray
  } catch (e) {
    console.trace('edit list could not be applied.')
  }
}

```
