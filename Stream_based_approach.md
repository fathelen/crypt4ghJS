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
