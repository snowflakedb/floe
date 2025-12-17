# Fast Lightweight Online Encryption

FLOE is a library that provides streaming capabilities for non-streamable by nature encryption algorithms (AEADs).
Currently, it supports AES-GCM-256 only.

## Parameters Specification

- `AEAD_ID` - Identifier of the AEAD algorithm to use. Currently, only `AES_GCM_256` is supported.
- `HASH_ID` - Identifier of the hash algorithm to use for encoding parameters. Currently, only `SHA384` is supported.
- `ENCRYPTED_SEGMENT_LENGTH` - Length of a ciphertext segment in bytes. The last segment can be shorter.
- `FLOE_IV_LENGTH` - Length of the IV used by FLOE. Currently, this value must be 32 bytes.

### Relationship between encrypted and plaintext segment lengths

While FLOE is configured using the length of ciphertext segments, it is often useful to know the corresponding length of plaintext segments (e.g. to know how many bytes of plaintext to pass to encryption).
The relationship between the two is defined as follows:

```
PLAINTEXT_SEGMENT_LENGTH = ENCRYPTED_SEGMENT_LENGTH - AEAD_IV_LENGTH - AEAD_TAG_LENGTH - 4
```

You can use `FloeParameterSpec.getPlainTextSegmentLength()` method to get the plaintext segment length.

## Java

To use the Java version of FLOE, include the following Maven dependency in your `pom.xml`:

```xml
<dependency>
    <groupId>net.snowflake</groupId>
    <artifactId>floe</artifactId>
    <version>REPLACE_ME</version>
</dependency>
```

Sample usage:

```java
FloeParameterSpec parameterSpec = FloeParameterSpec.GCM256_SHA384_4K; // or FloeParameterSpec.GCM256_SHA384_1M
Floe floe = Floe.getInstance(parameterSpec); 

// Encryption
try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
    baos.write(encryptor.getHeader());
    ByteBuffer plaintextSegment = ByteBuffer.wrap(new byte[parameterSpec.getPlainTextSegmentLength()]);
    byte[] plaintextSegmentPart = new byte[parameterSpec.getPlainTextSegmentLength()];
    do {
        int readBytes;
        do {
            readBytes = plaintextInputStream.read(plaintextSegmentPart, 0, plaintextSegment.remaining());
            if (readBytes == -1) {
                break;
            }
            plaintextSegment.put(plaintextSegmentPart, 0, readBytes);
        } while (plaintextSegment.hasRemaining());
        byte[] ciphertextSegment;
        ciphertextSegment = encryptor.processSegment(plaintextSegment.array(), 0, plaintextSegment.position());
        baos.write(ciphertextSegment, 0, ciphertextSegment.length);
        plaintextSegment.clear();
    } while(!encryptor.isClosed());
}

// Decryption
// optional - only if header is a part of the ciphertext stream
ByteBuffer header = ByteBuffer.wrap(new byte[parameterSpec.getHeaderSize()]);
byte[] headerPart = new byte[header.remaining()];
int readBytes;
do {
    readBytes = ciphertextInputStream.read(headerPart, 0, header.remaining());
if (readBytes == -1) {
    throw new IllegalStateException("stream does not provide full header");
}
  header.put(headerPart, 0, readBytes);
} while (header.hasRemaining());
    
// decrypting segments
try (FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, header.array())) {
    ByteBuffer ciphertextSegment = ByteBuffer.wrap(new byte[parameterSpec.getEncryptedSegmentLength()]);
    byte[] ciphertextSegmentPart = new byte[parameterSpec.getEncryptedSegmentLength()];
    do {
        do {
            readBytes = ciphertextInputStream.read(ciphertextSegmentPart, 0, ciphertextSegment.remaining());
            if (readBytes == -1) {
                break;
            }
            ciphertextSegment.put(ciphertextSegmentPart, 0, readBytes);
        } while (ciphertextSegment.hasRemaining());
        byte[] targetPlaintext = decryptor.processSegment(ciphertextSegment.array(), 0, ciphertextSegment.position());
        baos.write(targetPlaintext, 0, targetPlaintext.length);
        ciphertextSegment.clear();
    } while(!decryptor.isClosed());
}
```