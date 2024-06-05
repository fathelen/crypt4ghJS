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
function RecalculateEditlist(headerInformation){
  summedupEditlisst <- blocks2decrypt(HeaderInformation)[0]
  editlist <- blocks2decrypt(HeaderInformation)[1]
  blocksize <- 65536
  blockEven <- 0
  blocks <- new Map()
  FOR each index of editlist
     IF index modulo 2 equals 0 THEN
        blockEven <- ((summedupEditlist[index] minus 1) divided by blocksize) minus 1
     END IF
     ELSE THEN
        blockOdd <- ((summedupEditlist[index] minus 1) divided by blocksize) minus 1
        IF blockEven equals blockOdd THEN
          blocks <- editpairSameblock(editlist,blocksize,blocks, blockEven, blockOdd, i)
        END IF
        ELSE THEN
          blocks <- editpairDiffrentblock(editlist,blocksize,blocks, blockEven, blockOdd, i)
        END ELSE
     END ELSE
  END FOR
  RETURN [blocks, blocks2decrypt(HeaderInformation)[2]]
}


function blocks2decrypt(editlist)
  addedEdit <- []
  editOdd <- []
  j <- 0
  IF length of editlist modulo 2 equals 0 THEN
    unEven <- false
    FOR each index of editlist
      j <- j plus editlist[index]
      addedEdit <- addedEdit append j
    END FOR
  END IF
  ELSE THEN
    unEven <- true
    const sum <- sum of editlist
    const restvalue <- blocksize multiplied by ((sum divided by blocksize) plus 1n) minus sum
    editlist <- editlist append restvalue
    addedEdit <- append sum plus restvalue
  END ELSE
  RETURN [addedEdit, editlist, uneven]


function editpairSameblock(editlist, blocksize, blocks, bEven, bOdd, i)
  IF i smaller then 2 THEN
    IF editlist[i-1] greater then blocksize THEN
      blocks[bEven] <- [editlist[i - 1] minus  (bEven minus 1) multplied by blocksize]
    END IF
    ELSE THEN
      blocks[bEven] <- [editlist[i - 1]])
    END ELSE
  blocks[bEven] append editlist[i]
  END IF
  ELSE THEN
    IF blocks includes bOdd THEN
      blocks[bEven] append editlist[i - 1]
       blocks[bEven] append editlist[i]
    END IF
    ELSE THEN
      lastKey <- greates key in map blocks
      sum <- blocksize minus (sum of values for last key) plus (blocksize mulitplied by (bOdd minus lastKey minus 1))
      blocks[bEven] <-  editlist[i - 1] minus sum 
      blocks[bEven] append editlist[i]
    END ELSE
  END ELSE
  RETURN blocks 
```
Second step is to differentiate, if a chunk has to be decrypted and if so, if the chunk has to be fully or partly decrypted : 
```
chunkList = Map of chunks that need to be decrypted, key = chunk Number, value = edits for chunk
booleanEven = true if editlist is even, false if editlist is odd
chunk = current chunk
counter = counter of streamed chunks

function diffrentiateDecryption(chunkList, booleanEven,chunk, counter)
  IF chunkList and booleanEven equal false and chunkList contains counter THEN
    decryptedText <- decrypt(chunk)
    editedText <- streamEditlist(chunkList(counter), decrypted)
    RETURN editedText
 END IF
 ELSE IF chunkList and booleanEven equal true and  chunkList contains counter THEN
    decryptedText <- decrypt(chunk)
    editedText <- streamEditlist(chunkList(counter), decrypted)
    RERURN editedText
 END ELSE IF
 ELSE
    decryptedText <- decrypt(chunk)
    RETURN decryptedText
 END ELSE

```
After this recalculation the function ApplyEditList (page 15) from the [GA4GH File Encryption Standard](http://samtools.github.io/hts-specs/crypt4gh.pdf) can be used to edit the decrypted text.
