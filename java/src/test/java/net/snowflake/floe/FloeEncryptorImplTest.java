package net.snowflake.floe;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FloeEncryptorImplTest {
  byte[] aad = "This is AAD".getBytes(StandardCharsets.UTF_8);
  SecretKey secretKey = new SecretKeySpec(new byte[32], "FLOE");

  @Test
  void shouldCreateCorrectHeader() throws Exception {
    IncrementingSecureRandom random = new IncrementingSecureRandom(18);
    FloeParameterSpec parameterSpec =
        new FloeParameterSpec(
            Aead.AES_GCM_256,
            Hash.SHA384,
            12345678,
            32,
            4,
            1L << 40);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(new SecretKeySpec(new byte[32], "FLOE"), "test aad".getBytes(StandardCharsets.UTF_8), random)) {
      byte[] header = encryptor.getHeader();
      // AEAD ID
      assertEquals(Aead.AES_GCM_256.getId(), header[0]);
      // HASH ID
      assertEquals(Hash.SHA384.getId(), header[1]);
      // Segment length in BE
      // 12345678(10) = BC614E(16)
      assertEquals(0, header[2]);
      assertEquals((byte) 188, header[3]);
      assertEquals((byte) 97, header[4]);
      assertEquals((byte) 78, header[5]);
      // FLOE IV length in BE
      // 32(10) = 00,00,00,32
      assertEquals(0, header[6]);
      assertEquals(0, header[7]);
      assertEquals(0, header[8]);
      assertEquals(32, header[9]);
      // FLOE IV
      assertEquals(0, header[10]);
      assertEquals(0, header[11]);
      assertEquals(0, header[12]);
      assertEquals(18, header[13]);

      addLastSegment(encryptor);
    }
  }

  private static byte[] addLastSegment(FloeEncryptor encryptor) throws FloeException {
    return encryptor.processSegment(new byte[0]);
  }

  @Test
  void shouldThrowExceptionOnMaxSegmentReached() throws Exception {
    FloeParameterSpec parameterSpec =
        new FloeParameterSpec(
            Aead.AES_GCM_256, Hash.SHA384, 40,32, 20, 3L);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      byte[] plaintext = new byte[8];
      encryptor.processSegment(plaintext);
      encryptor.processSegment(plaintext);
      assertThrows(FloeException.class, () -> encryptor.processSegment(plaintext));
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {9, 1024})
  void shouldThrowExceptionIfPlaintextIsTooLong(int segmentSize) throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      FloeException e = assertThrows(FloeException.class, () -> encryptor.processSegment(new byte[segmentSize]));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals(e.getCause().getMessage(), "segment length mismatch, expected at most 8, got " + segmentSize);

      addLastSegment(encryptor);
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {9, 1024})
  void shouldThrowExceptionIfPlaintextIsTooLongWhenCallingWithZeroOffset(int segmentSize) throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      FloeException e = assertThrows(FloeException.class, () -> encryptor.processSegment(new byte[segmentSize], 0, segmentSize));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals(e.getCause().getMessage(), "segment length mismatch, expected at most 8, got " + segmentSize);

      addLastSegment(encryptor);
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {9, 1024})
  void shouldThrowExceptionIfPlaintextIsTooLongWhenCallingWithNonZeroOffset(int segmentSize) throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      FloeException e = assertThrows(FloeException.class, () -> encryptor.processSegment(new byte[segmentSize], 1, segmentSize));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals(e.getCause().getMessage(), "segment length mismatch, expected at most 8, got " + segmentSize);

      addLastSegment(encryptor);
    }
  }

  @Test
  void shouldThrowExceptionIfPlaintextOffsetAndLengthAreLargerThanSegmentSize() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      FloeException e = assertThrows(FloeException.class, () -> encryptor.processSegment(new byte[8], 1, 8));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals(e.getCause().getMessage(), "invalid offset (1) and length (8) for input length (8)");

      addLastSegment(encryptor);
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 7})
  void shouldAcceptSegmentWithCorrectSize(int lastSegmentSize) throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      assertDoesNotThrow(() -> encryptor.processSegment(new byte[8]));
      assertDoesNotThrow(() -> encryptor.processSegment(new byte[lastSegmentSize]));
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 7})
  void shouldAcceptSegmentWithCorrectSizeWithOffsetAndLength(int lastSegmentSize) throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      assertDoesNotThrow(() -> encryptor.processSegment(new byte[8], 0, 8));
      assertDoesNotThrow(() -> encryptor.processSegment(new byte[lastSegmentSize], 0, lastSegmentSize));
    }
  }

  @Test
  void shouldNotAcceptNewSegmentsAfterLastOneIsProcessed() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      assertFalse(encryptor.isClosed());
      encryptor.processSegment(new byte[4]);
      assertTrue(encryptor.isClosed());
      IllegalStateException e =
          assertThrows(IllegalStateException.class, () -> encryptor.processSegment(new byte[4]));
      assertEquals("stream has already been closed", e.getMessage());
      e =
          assertThrows(
              IllegalStateException.class, () -> encryptor.processSegment(new byte[4]));
      assertEquals("stream has already been closed", e.getMessage());
    }
  }

  @Test
  void correctSegmentShouldClearExceptionalMarkerAndFailOnClosingIfLastSegmentIsNotProcessed() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);

    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad); FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
      // incorrect segment
      assertThrows(FloeException.class, () -> encryptor.processSegment(new byte[9]));

      // correct segment clears the encryptor
      byte[] firstSegmentCiphertext = encryptor.processSegment(new byte[8]);
      byte[] lastSegmentCiphertext = encryptor.processSegment(new byte[4]);

      // incorrect segment
      assertThrows(FloeException.class, () -> decryptor.processSegment(new byte[9]));

      // correct segment clears the decryptor
      assertArrayEquals(new byte[8], decryptor.processSegment(firstSegmentCiphertext));
      assertArrayEquals(new byte[4], decryptor.processSegment(lastSegmentCiphertext));
    }
  }

  @Test
  void shouldThrowExceptionForNegativeOffset() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      FloeException e = assertThrows(FloeException.class, () -> encryptor.processSegment(new byte[8], -1, 8));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals(e.getCause().getMessage(), "invalid offset (-1) and length (8) for input length (8)");
      encryptor.processSegment(new byte[0]);
    }
  }

  @Test
  void shouldThrowExceptionForNegativeLength() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      FloeException e = assertThrows(FloeException.class, () -> encryptor.processSegment(new byte[8], 0, -5));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals(e.getCause().getMessage(), "invalid offset (0) and length (-5) for input length (8)");
      encryptor.processSegment(new byte[0]);
    }
  }
}
