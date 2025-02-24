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
import java.util.Arrays;

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
    byte[] header;
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      header = encryptor.getHeader();
      byte[] plaintextSegment = new byte[parameterSpec.getPlainTextSegmentLength()];
      do {
        int readBytes = plaintextInputStream.read(plaintextSegment);
        byte[] ciphertext;
        if (readBytes == -1) {
          ciphertext = encryptor.processLastSegment(new byte[0]);
        } else if (readBytes == parameterSpec.getPlainTextSegmentLength()) {
          ciphertext = encryptor.processSegment(plaintextSegment);
        } else {
          // TODO SNOW-1322063 add API for reusing bigger byte array
          byte[] lastPlaintextSegment = Arrays.copyOf(plaintextSegment, readBytes);
          ciphertext = encryptor.processLastSegment(lastPlaintextSegment);
        }
        baos.write(ciphertext);
      } while(!encryptor.isClosed());
    }

    // DECRYPTION PHASE
    byte[] ciphertext = baos.toByteArray();
    InputStream ciphertextInputStream = new ByteArrayInputStream(ciphertext);
    baos = new ByteArrayOutputStream();
    try (FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, header)) {
      byte[] ciphertextSegment = new byte[parameterSpec.getEncryptedSegmentLength()];
      do {
        int readBytes = ciphertextInputStream.read(ciphertextSegment);
        byte[] targetPlaintext;
        if (readBytes == -1) {
          break;
        } else if (readBytes == parameterSpec.getEncryptedSegmentLength()) {
          targetPlaintext = decryptor.processSegment(ciphertextSegment);
        } else {
          byte[] lastCiphertextSegment = Arrays.copyOf(ciphertextSegment, readBytes);
          targetPlaintext = decryptor.processSegment(lastCiphertextSegment);
        }
        baos.write(targetPlaintext);
      } while(!decryptor.isClosed());
    }
    assertArrayEquals(plaintext, baos.toByteArray());
  }
}
