package net.snowflake.floe;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class FloeE2ETest {
  private final SecureRandom random = new SecureRandom();
  SecretKey secretKey = new SecretKeySpec(new byte[32], "AES");
  byte[] aad = new byte[32];

  FloeParameterSpec parameterSpec4kB = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 4 * 1024, 32);
  FloeParameterSpec parameterSpec1MB = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 1024 * 1024, 32);

  @ParameterizedTest
  @ValueSource(ints = {
      200, // multiple of plaintext segment size
      301, // and the oposite
  })
  void runForVariousPlaintextSizesRelatedToParameters(int plaintextSize) throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    run(parameterSpec, plaintextSize);
  }

  @Test
  void runFor4kB() throws Exception {
    runForVariousPlaintextSizes(parameterSpec4kB);
  }

  @Test
  void runFor1MB() throws Exception {
    runForVariousPlaintextSizes(parameterSpec1MB);
  }

  private void runForVariousPlaintextSizes(FloeParameterSpec parameterSpec) throws Exception {
    run(parameterSpec, 100);
    run(parameterSpec, parameterSpec.getPlainTextSegmentLength() - 1);
    run(parameterSpec, parameterSpec.getPlainTextSegmentLength());
    run(parameterSpec, parameterSpec.getPlainTextSegmentLength() + 1);
    run(parameterSpec, parameterSpec.getPlainTextSegmentLength() * 2);
    run(parameterSpec, parameterSpec.getPlainTextSegmentLength() * 2 + 1);
  }

  private void run(FloeParameterSpec parameterSpec, int plaintextSize) throws Exception {
    Floe floe = Floe.getInstance(parameterSpec);

    // ENCRYPTION PHASE
    byte[] plaintext = new byte[plaintextSize];
    random.nextBytes(plaintext);
    InputStream plaintextInputStream = new ByteArrayInputStream(plaintext);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      baos.write(encryptor.getHeader());
      byte[] plaintextSegment = new byte[parameterSpec.getPlainTextSegmentLength()];
      do {
        int readBytes = plaintextInputStream.read(plaintextSegment);
        byte[] ciphertext;
        if (readBytes != parameterSpec.getPlainTextSegmentLength()) {
          ciphertext = encryptor.processLastSegment(plaintextSegment, 0, readBytes);
        } else {
          ciphertext = encryptor.processSegment(plaintextSegment, 0, readBytes);
        }
        baos.write(ciphertext, 0, ciphertext.length);
      } while(!encryptor.isClosed());
    }

    // DECRYPTION PHASE
    byte[] ciphertext = baos.toByteArray();
    InputStream ciphertextInputStream = new ByteArrayInputStream(ciphertext);
    baos = new ByteArrayOutputStream();

    byte[] header = new byte[parameterSpec.getHeaderSize()];
    ciphertextInputStream.read(header);

    try (FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, header)) {
      byte[] ciphertextSegment = new byte[parameterSpec.getEncryptedSegmentLength()];
      do {
        int readBytes = ciphertextInputStream.read(ciphertextSegment);
        byte[] targetPlaintext = decryptor.processSegment(ciphertextSegment, 0, readBytes);
        baos.write(targetPlaintext, 0, targetPlaintext.length);
      } while(!decryptor.isClosed());
    }
    assertArrayEquals(plaintext, baos.toByteArray());
  }
}
