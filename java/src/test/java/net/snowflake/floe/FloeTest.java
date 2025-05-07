package net.snowflake.floe;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
              40,
              32,
              4,
              1L << 40);
      Floe floe = Floe.getInstance(parameterSpec);
      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad, new IncrementingSecureRandom(678765));
           FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
        byte[] testData = new byte[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
        byte[] ciphertext = encryptor.processSegment(testData, 2, 4);
        byte[] result = decryptor.processSegment(ciphertext);
        assertArrayEquals(new byte[]{'c', 'd', 'e', 'f'}, result);
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
