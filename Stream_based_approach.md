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
code (MAC) used for the chacha20-ietf-poly1305 encryption.

## Transformation of edit lists
Since the streamed chunks are decrypted individually, the editlist has to be recalculated to know, which chunks have to be fully or partly decrypted. 
We implemented this process in two steps.
<br> 
<br> 
First step is to recalculate the editlist fitted to the stream based approach : 
```
function streamEditlist(editlist)
  Blocks2decrypt = blocks2decrypt(editlist)
  ChunkMap = Map()
  repeat:
    if (i % 2 === 0) then
      bEven = (Blocks2decrypt[0][i] - 1) / 65536 + 1
    else
      bOdd = (Blocks2decrypt[0][i] - 1) / 65536 + 1
      if (bEven === bOdd) then
       if (((Blocks2decrypt[0][i - 2] - 1) / 65536 + 1) === bOdd) {
          ChunkMap[bEven].push(preEdit[1][i - 1]])
          ChunkMap[bEven].push(preEdit[1][i]])
        } else {
          const sum = 65536 - ( sum(ChunkMap[bEven - 1]) + 65536 * (bOdd - 2)
          ChunkMap[bEven].push(preEdit[1][i - 1] - sum])
          ChunkMap[bEven].push(preEdit[1][i]])
        }
      else
        if (ChunkMap.contains(bEven))
          if (ChunkMap[1][i - 1] > 65536) 
            CunkMap[bEven].push(preEdit[1][i - 1] - (bEven - 1) * 65536])
          else 
            CunkMap[bEven].push(preEdit[1][i - 1]])



  until len(Blocks2decrypt[0])

function blocks2decrypt(editlist)

  if (len(editlist) % 2 === 0) then
   unEnven = false
   repeat:
    sumEditlist = sumEditlist.push(sum(editlist[i]))
    unitil i = len(editlist)
  else:
    unEven = true
    sum = (editlist.reduce((partialSum, a) => partialSum + a, 0n))
    editOdd.set(editlist)
    editOdd[editOdd.length - 1] = 65536n * ((sum / 65536n) + 1n) - sum
    repeat:
      j = j + editOdd[i]
      sumEditlist = sumEditlist.push(sum(editOdd[i]))
    unitil i = len(editOdd)
    editlist = editOdd
 return [sumEditlist, editlist, unEven]
```
Second step is to differentiate, if a chunk has to be decrypted and if so, if the chunk has to be fully or partly decrypted : 
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
After this recalculation the function ApplyEditList (page 15) from the [GA4GH File Encryption Standard](http://samtools.github.io/hts-specs/crypt4gh.pdf) can be used to edit the decrypted text.
