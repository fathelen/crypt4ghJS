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
First step is to recalculate the editlist fitted to the stream based approach : 
```

chunkList = Map of chunks that need to be decrypted, key = chunk Number, value = edits for chunk
booleanEven = true if editlist is even, false if editlist is odd
chunk = current chunk
counter = counter of streamed chunks

function diffrentiateDecryption(chunkList, booleanEven,chunk, counter)
  if(chunkList & booleanEven == false & chunkList.contains(counter) then
    decryptedText <- decrypt(chunk)
    editedText <- streamEditlist(chunkList(counter), decrypted)
    return editedText
 else if(chunkList & booleanEven == true & chunkList.contains(counter) then
    decryptedText <- decrypt(chunk)
    editedText <- streamEditlist(chunkList(counter), decrypted)
    return editedText
 else
    decryptedText <- decrypt(chunk)
    return <- decryptedText
    
    


```
Second step is to differentiate, if a chunk has to be decrypted and if so, if the chunk has to be fully or partly decrypted : 
```

function calculateEditlist (headerInformation) {
  const preEdit = blocks2encrypt(headerInformation)
  let bEven = 0
  const blocks = new Map()
  for (let i = 0; i < preEdit[0].length; i++) {
    if (i % 2 === 0) {
      bEven = Number(((preEdit[0][i] - 1n) / 65536n) + 1n)
    } else {
      const bOdd = Number(((preEdit[0][i] - 1n) / 65536n) + 1n)
      if (bEven === bOdd && i >= 2) {
        if (Number(((preEdit[0][i - 2] - 1n) / 65536n) + 1n) === bOdd) {
          blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i - 1]])
          blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i]])
        } else {
          const lastKey = [...blocks.keys()].pop()
          const sum = 65536n - ((blocks.get(lastKey).reduce((partialSum, a) => partialSum + a, 0n))) + BigInt((65536 * (bOdd - 2)))
          blocks.set(bEven, [preEdit[1][i - 1] - sum])
          blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i]])
        }
      } else if (bEven === bOdd && i < 2) {
        if (blocks.has(bEven)) {
          if (preEdit[1][i - 1] > 65536n) {
            blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i - 1] - (BigInt(bEven - 1) * 65536n)])
          } else {
            blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i - 1]])
          }
        } else {
          if (preEdit[1][i - 1] > 65536n) {
            blocks.set(bEven, [preEdit[1][i - 1] - (BigInt(bEven - 1) * 65536n)])
          } else {
            blocks.set(bEven, [preEdit[1][i - 1]])
          }
        }
        blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i]])
      } else if (bEven !== bOdd) {
        if (blocks.has(bEven)) {
          if (preEdit[1][i - 1] > 65536n) {
            blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i - 1] - (BigInt(bEven - 1) * 65536n)])
          } else {
            blocks.set(bEven, [...blocks.get(bEven), preEdit[1][i - 1]])
          }
        } else {
          if (preEdit[1][i - 1] > 65536n) {
            blocks.set(bEven, [preEdit[1][i - 1] - (BigInt(bEven - 1) * 65536n)])
          } else {
            blocks.set(bEven, [preEdit[1][i - 1]])
          }
        }
        if (preEdit[1][i - 1] > 65536) {
          blocks.set(bEven, [...blocks.get(bEven), 65536n * BigInt(bEven) - preEdit[1][i - 1]])
        } else {
          blocks.set(bEven, [...blocks.get(bEven), 65536n - preEdit[1][i - 1]])
        }
        const lastKey = [...blocks.keys()].pop()
        const x = (preEdit[1][i] / 65536n)
        if (preEdit[1][i] > 65536n) {
          for (let j = lastKey + 1; j < Number(x + 1n); j++) {
            blocks.set(j, [0n, 65536n])
          }
        }
        blocks.set(bOdd, [0n])
        if (Number(x) > 0) {
          if (preEdit[1][i - 1] > 65536) {
            blocks.set(bOdd, [...blocks.get(bOdd), preEdit[1][i] - (65536n * BigInt(bEven) - preEdit[1][i - 1])])
          } else {
            blocks.set(bOdd, [...blocks.get(bOdd), preEdit[1][i] - (65536n * x - preEdit[1][i - 1])])
          }
        } else {
          if (preEdit[1][i - 1] > 65536) {
            blocks.set(bOdd, [...blocks.get(bOdd), preEdit[1][i] - (65536n * BigInt(bEven) - preEdit[1][i - 1])])
          } else {
            blocks.set(bOdd, [...blocks.get(bOdd), preEdit[1][i] - (65536n * (x + 1n) - preEdit[1][i - 1])])
          }
        }
      }
    }
  }
  return [blocks, preEdit[2]]
}

function blocks2encrypt (headerInformation) {
  // 1.Step: Welche Blöcke müssen entschlüsselt werden
  const edit64 = new BigInt64Array(headerInformation[3][0].buffer)
  let editlist = edit64.subarray(1)
  let addedEdit = []
  let j = 0n
  for (let i = 0; i < editlist.length; i++) {
    j = j + editlist[i]
    addedEdit.push(j)
  }
  // ungerade editlist anpassen
  let unEven = false
  const editOdd = new BigInt64Array(editlist.length + 1)
  if (editlist.length % 2 !== 0) {
    unEven = true
    const sum = (editlist.reduce((partialSum, a) => partialSum + a, 0n))
    editOdd.set(editlist)
    editOdd[editOdd.length - 1] = 65536n * ((sum / 65536n) + 1n) - sum
  }
  // 2.Map erstellen
  if (editlist.length % 2 !== 0) {
    addedEdit = []
    editlist = editOdd
    let j = 0n
    for (let i = 0; i < editlist.length; i++) {
      j = j + editlist[i]
      addedEdit.push(j)
    }
  }
  return [addedEdit, editlist, unEven]
}

```
After this recalculation the function ApplyEditList (page 15) from the [GA4GH File Encryption Standard](http://samtools.github.io/hts-specs/crypt4gh.pdf) can be used to edit the decrypted text.
