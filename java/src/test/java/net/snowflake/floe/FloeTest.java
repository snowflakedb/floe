package net.snowflake.floe;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FloeTest {
  byte[] aad = "This is AAD".getBytes(StandardCharsets.UTF_8);
  SecretKey secretKey = new SecretKeySpec(new byte[32], "FLOE");

  @Nested
  class HeaderTests {
    @Test
    void validateHeaderMatchesForEncryptionAndDecryption() throws Exception {
      FloeParameterSpec parameterSpec =
          new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 1024, 4);
      Floe floe = Floe.getInstance(parameterSpec);

      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad);
          FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
        decryptor.processSegment(encryptor.processSegment(new byte[0]));
      }
    }

    @Test
    void validateHeaderDoesNotMatchInParams() throws Exception {
      FloeParameterSpec parameterSpec =
          new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 1024, 4);
      Floe floe = Floe.getInstance(parameterSpec);
      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
        byte[] header = encryptor.getHeader();
        header[0] = 12;
        IllegalArgumentException e =
            assertThrows(
                IllegalArgumentException.class, () -> floe.createDecryptor(secretKey, aad, header));
        assertEquals(e.getMessage(), "invalid parameters header");
        encryptor.processSegment(new byte[0]); // ensure encryptor is closed
      }
    }

    @Test
    void validateHeaderDoesNotMatchInIV() throws Exception {
      FloeParameterSpec parameterSpec =
          new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 1024, 4);
      Floe floe = Floe.getInstance(parameterSpec);
      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
        byte[] header = encryptor.getHeader();
        header[11]++;
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> floe.createDecryptor(secretKey, aad, header));
        assertEquals(e.getMessage(), "invalid header tag");
        encryptor.processSegment(new byte[0]); // ensure encryptor is closed
      }
    }

    @Test
    void validateHeaderDoesNotMatchInHeaderTag() throws Exception {
      FloeParameterSpec parameterSpec =
          new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 4096, 4);
      Floe floe = Floe.getInstance(parameterSpec);
      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
        byte[] header = encryptor.getHeader();
        header[header.length - 3]++;
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> floe.createDecryptor(secretKey, aad, header));
        assertEquals(e.getMessage(), "invalid header tag");
        encryptor.processSegment(new byte[0]); // ensure encryptor is closed
      }
    }
  }

  @Nested
  class ValidInputTests {
    @Test
    public void keyLengthIsChecked() throws Exception {
      final SecretKey longKey = new SecretKeySpec(new byte[33], "FLOE");
      final SecretKey validKey = new SecretKeySpec(new byte[32], "FLOE");
      final FloeParameterSpec parameterSpec =
          new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 4096, 32);
      final Floe floe = Floe.getInstance(parameterSpec);
      IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> floe.createEncryptor(longKey, aad));
      assertEquals("invalid key length", e.getMessage());

      try (FloeEncryptor encryptor = floe.createEncryptor(validKey, aad)) {
        // Check the decryption flow
        e = assertThrows(IllegalArgumentException.class, () -> floe.createDecryptor(longKey, aad, encryptor.getHeader()));
        assertEquals("invalid key length", e.getMessage());
        // Finish encryption to avoid error
        encryptor.processSegment(new byte[0]);
      }
    }
  }

  @Nested
  class SegmentTests {

    @Test
    void testSegmentEncryptedAndDecrypted() throws Exception {
      FloeParameterSpec parameterSpec =
          new FloeParameterSpec(
              Aead.AES_GCM_256,
              Hash.SHA384,
              40,
              32,
              4,
              1L << 40);
      Floe floe = Floe.getInstance(parameterSpec);
      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad, new IncrementingSecureRandom(678765));
          FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
        byte[] testData = new byte[8];
        byte[] ciphertext = encryptor.processSegment(testData);
        byte[] result = decryptor.processSegment(ciphertext);
        assertArrayEquals(testData, result);
        closeEncryptorAndDecryptor(encryptor, decryptor);
      }
    }

    @Test
    void testSegmentEncryptedAndDecryptedWithOffsetAndLimit() throws Exception {
      FloeParameterSpec parameterSpec =
          new FloeParameterSpec(
              Aead.AES_GCM_256,
              Hash.SHA384,
              34,
              32,
              4,
              1L << 40);
      Floe floe = Floe.getInstance(parameterSpec);
      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad, new IncrementingSecureRandom(678765));
           FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
        byte[] testData = new byte[]{'a', 'b', 'c', 'd'};
        ByteBuffer ciphertextBuf = ByteBuffer.allocate(parameterSpec.getEncryptedSegmentLength() * 3);
        ciphertextBuf.put(encryptor.processSegment(testData, 0, parameterSpec.getPlainTextSegmentLength()));
        ciphertextBuf.put(encryptor.processSegment(testData, parameterSpec.getPlainTextSegmentLength(), parameterSpec.getPlainTextSegmentLength()));
        ciphertextBuf.put(encryptor.processSegment(testData, 2 * parameterSpec.getPlainTextSegmentLength(), 0));
        byte[] ciphertext = ciphertextBuf.array();
        ByteBuffer plaintextBuf = ByteBuffer.allocate(testData.length);
        plaintextBuf.put(decryptor.processSegment(ciphertext, 0, parameterSpec.getEncryptedSegmentLength()));
        plaintextBuf.put(decryptor.processSegment(ciphertext, parameterSpec.getEncryptedSegmentLength(), parameterSpec.getEncryptedSegmentLength()));
        plaintextBuf.put(decryptor.processSegment(ciphertext, 2 * parameterSpec.getEncryptedSegmentLength(), parameterSpec.getEncryptedSegmentLength() - parameterSpec.getPlainTextSegmentLength()));
        byte[] result = plaintextBuf.array();
        assertArrayEquals(testData, result);
      }
    }

    @Test
    void testSegmentEncryptedAndDecryptedWithRandomData() throws Exception {
      FloeParameterSpec parameterSpec =
          new FloeParameterSpec(
              Aead.AES_GCM_256,
              Hash.SHA384,
              40,
              32,
              4,
              1L << 40);
      Floe floe = Floe.getInstance(parameterSpec);
      byte[] ciphertext;
      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad, new IncrementingSecureRandom(678765));
          FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
        byte[] testData = new byte[8];
        new SecureRandom().nextBytes(testData);
        ciphertext = encryptor.processSegment(testData);
        byte[] result = decryptor.processSegment(ciphertext);
        assertArrayEquals(testData, result);
        closeEncryptorAndDecryptor(encryptor, decryptor);
      }
    }

    @Test
    void testSegmentEncryptedAndDecryptedWithDerivedKeyRotation() throws Exception {
      FloeParameterSpec parameterSpec =
          new FloeParameterSpec(
              Aead.AES_GCM_256,
              Hash.SHA384,
              40,
              32,
              4,
              1L << 40);
      Floe floe = Floe.getInstance(parameterSpec);
      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad, new IncrementingSecureRandom(6546));
          FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
        byte[] testData = new byte[8];
        for (int i = 0; i < 10; i++) {
          byte[] ciphertext = encryptor.processSegment(testData);
          byte[] result = decryptor.processSegment(ciphertext);
          assertArrayEquals(testData, result);
        }
        byte[] ciphertext = encryptor.processSegment(testData);
        decryptor.processSegment(ciphertext);
        closeEncryptorAndDecryptor(encryptor, decryptor);
      }
    }

    private void closeEncryptorAndDecryptor(FloeEncryptor encryptor, FloeDecryptor decryptor) {
      byte[] lastSegment = encryptor.processSegment(new byte[0]);
      decryptor.processSegment(lastSegment);
    }
  }

  @Nested
  class LastSegmentTests {
    @Test
    void testLastSegmentEncryptedAndDecrypted() throws Exception {
      FloeParameterSpec parameterSpec =
          new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 1024, 32);
      Floe floe = Floe.getInstance(parameterSpec);
      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad);
           FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
        byte[] plaintext = new byte[3];
        byte[] encrypted = encryptor.processSegment(plaintext);
        byte[] decrypted = decryptor.processSegment(encrypted);
        assertArrayEquals(plaintext, decrypted);
      }
    }
  }
}
