package net.snowflake.floe;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static net.snowflake.floe.FloeTest.toHex;
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
    FloeParameterSpec parameterSpec =
        new FloeParameterSpec(
            Aead.AES_GCM_256,
            Hash.SHA384,
            12345678,
            4,
            4,
            1L << 40);
    FloeKey floeKey = new FloeKey(new SecretKeySpec(new byte[32], "FLOE"));
    FloeAad floeAad = new FloeAad("test aad".getBytes(StandardCharsets.UTF_8));
    try (FloeEncryptor encryptor = new FloeEncryptorImpl(parameterSpec, floeKey, floeAad, new IncrementingSecureRandom(18))) {
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
      // 4(10) = 4(16) = 00,00,00,04
      assertEquals(0, header[6]);
      assertEquals(0, header[7]);
      assertEquals(0, header[8]);
      assertEquals(4, header[9]);
      // FLOE IV
      assertEquals(0, header[10]);
      assertEquals(0, header[11]);
      assertEquals(0, header[12]);
      assertEquals(18, header[13]);

      addLastSegment(encryptor);
    }
  }

  private static byte[] addLastSegment(FloeEncryptor encryptor) throws FloeException {
    return encryptor.processLastSegment(new byte[0]);
  }

  @Test
  void testEncryptionMatchesReference() throws Exception {
    List<String> referenceCiphertextSegments =
        Arrays.asList(
            "ffffffff0000000100000000000000000100007f5713b9827bb806318311fcde197146a144c6b485", // pragma: allowlist secret
            "ffffffff000000020000000000000000f926dfc0a0bac6263d1634ad9a72f86900872033a271a037", // pragma: allowlist secret
            "ffffffff00000003000000000000000080df8fdee872febe574c2b8df0bb34b3fb25bfc5802703a2", // pragma: allowlist secret
            "ffffffff000000040000000000000000f4d81083e57451dbfa538827942245019b8bc3354ecc31e0", // pragma: allowlist secret
            "ffffffff000000050000000000000000d91b774b5b460bd665910114e155f1cbc55a9a262a54f65e", // pragma: allowlist secret
            "ffffffff000000060000000000000000ec723f3807eb71ea42ff03f5420daf34e1a8f4fb58931db1", // pragma: allowlist secret
            "ffffffff00000007000000000000000072960c06ec19ce94c27c9fc72d79164f187f37e86325d849", // pragma: allowlist secret
            "ffffffff000000080000000000000000c00a40fb140d797da818ab57399cb986bddddd174b8d3d6a", // pragma: allowlist secret
            "ffffffff000000090000000000000000065e959cd1ffa521896fb54949a57ad1c1f8291a531c6d60", // pragma: allowlist secret
            "ffffffff0000000a0000000000000000dfde3da3f67a081fb31229ac11e43a629ed120fbf9942513" // pragma: allowlist secret
            );
    FloeParameterSpec parameterSpec =
        new FloeParameterSpec(
            Aead.AES_GCM_256,
            Hash.SHA384,
            40,
            32,
            4,
            1L << 40);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad, new IncrementingSecureRandom(0));
        FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
      byte[] testData = new byte[8];
      for (String referenceCiphertextSegment : referenceCiphertextSegments) {
        byte[] ciphertextBytes = encryptor.processSegment(testData);
        String ciphertextHex = toHex(ciphertextBytes);
        assertEquals(referenceCiphertextSegment, ciphertextHex);
        byte[] plaintextBytes = decryptor.processSegment(ciphertextBytes);
        assertArrayEquals(testData, plaintextBytes);
      }

      byte[] lastSegment = encryptor.processLastSegment(new byte[0]);
      decryptor.processSegment(lastSegment);
    }
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
      assertDoesNotThrow(() -> encryptor.processLastSegment(plaintext));
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 7, 9, 1024})
  void shouldThrowExceptionIfPlaintextLengthIsIncorrect(int segmentSize) throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      FloeException e = assertThrows(FloeException.class, () -> encryptor.processSegment(new byte[segmentSize]));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals(e.getCause().getMessage(), "segment length mismatch, expected 8, got " + segmentSize);

      addLastSegment(encryptor);
    }
  }

  @Test
  void shouldThrowEncryptionIfLastSegmentPlaintextIsTooLong() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      FloeException e =
          assertThrows(
              FloeException.class, () -> encryptor.processLastSegment(new byte[9]));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals(e.getCause().getMessage(), "last segment is too long, got 9, max is 8");

      addLastSegment(encryptor);
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 8})
  void shouldAcceptSegmentWithCorrectSize(int lastSegmentSize) throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      assertDoesNotThrow(() -> encryptor.processSegment(new byte[8]));
      assertDoesNotThrow(() -> encryptor.processLastSegment(new byte[lastSegmentSize]));
    }
  }

  @Test
  void shouldNotAcceptNewSegmentsAfterLastOneIsProcessed() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      assertFalse(encryptor.isClosed());
      encryptor.processLastSegment(new byte[4]);
      assertTrue(encryptor.isClosed());
      IllegalStateException e =
          assertThrows(IllegalStateException.class, () -> encryptor.processSegment(new byte[4]));
      assertEquals("stream has already been closed", e.getMessage());
      e =
          assertThrows(
              IllegalStateException.class, () -> encryptor.processLastSegment(new byte[4]));
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
      byte[] lastSegmentCiphertext = encryptor.processLastSegment(new byte[8]);

      // incorrect segment
      assertThrows(FloeException.class, () -> decryptor.processSegment(new byte[9]));

      // correct segment clears the decryptor
      assertArrayEquals(new byte[8], decryptor.processSegment(firstSegmentCiphertext));
      assertArrayEquals(new byte[8], decryptor.processSegment(lastSegmentCiphertext));
    }
  }
}
