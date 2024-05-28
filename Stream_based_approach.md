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
