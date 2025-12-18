package net.snowflake.floe;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FloeDecryptorImplTest {
  private final SecretKey secretKey = new SecretKeySpec(new byte[32], "AES");
  private final byte[] aad = "Test AAD".getBytes(StandardCharsets.UTF_8);

  @ParameterizedTest
  @ValueSource(ints = {0, 7, 800})
  void shouldThrowExceptionWhenHeaderHasIncorrectLength(int headerSize) {
    Floe floe = Floe.getInstance(FloeParameterSpec.GCM256_SHA384_4K);
    assertThrows(IllegalArgumentException.class, () -> floe.createDecryptor(secretKey, aad, new byte[headerSize]));
  }

  @Test
  void shouldDecryptCiphertext() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad);
        FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
      byte[] firstSegment = encryptor.processSegment(new byte[8]);
      byte[] lastSegment = encryptor.processSegment(new byte[4]);

      assertArrayEquals(new byte[8], decryptor.processSegment(firstSegment));
      assertFalse(decryptor.isClosed());
      assertArrayEquals(new byte[4], decryptor.processSegment(lastSegment));
      assertTrue(decryptor.isClosed());
    }
  }

  @Test
  void shouldDecryptLastSegmentZeroLength() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad);
        FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
      byte[] lastSegment = encryptor.processSegment(new byte[0]);
      assertArrayEquals(new byte[0], decryptor.processSegment(lastSegment));
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 7, 0})
  void shouldThrowExceptionIfSegmentLengthIsMismatched(int plaintextSegmentLength) throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad);
        FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
      byte[] ciphertext = encryptor.processSegment(new byte[plaintextSegmentLength]);
      byte[] prunedCiphertext = new byte[12];
      ByteBuffer.wrap(ciphertext).get(prunedCiphertext);
      FloeException e = assertThrows(FloeException.class, () -> decryptor.processSegment(prunedCiphertext));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals("segment length too short, expected at least 32, got 12", e.getCause().getMessage());
      byte[] extendedCiphertext = new byte[1024];
      ByteBuffer.wrap(extendedCiphertext).put(ciphertext);
      e = assertThrows(FloeException.class, () -> decryptor.processSegment(extendedCiphertext));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals("segment length mismatch, expected at most 40, got 1024", e.getCause().getMessage());
      if (plaintextSegmentLength == parameterSpec.getPlainTextSegmentLength()) {
        encryptor.processSegment(new byte[0]);
      }
    }
  }

  @Test
  void shouldThrowExceptionIfLastSegmentLengthIsMismatched() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad);
        FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
      encryptor.processSegment(new byte[4]);
      FloeException e =
          assertThrows(
              FloeException.class, () -> decryptor.processSegment(new byte[12]));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals("segment length too short, expected at least 32, got 12", e.getCause().getMessage());
    }
  }

  @Test
  void shouldThrowExceptionIfLastSegmentLengthMarkerDoesNotMatchActualLength() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad);
        FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
      encryptor.processSegment(new byte[4]);
      FloeException e =
          assertThrows(
              FloeException.class, () -> decryptor.processSegment(new byte[40]));
      assertInstanceOf(IllegalArgumentException.class, e.getCause());
      assertEquals("segment length mismatch, expected 0, got 40", e.getCause().getMessage());
    }
  }

  @Test
  void shouldThrowExceptionIfSegmentIsTampered() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad);
        FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
      byte[] ciphertext = encryptor.processSegment(new byte[8]);
      ciphertext[39]++;
      FloeException e =
          assertThrows(FloeException.class, () -> decryptor.processSegment(ciphertext));
      assertInstanceOf(AEADBadTagException.class, e.getCause());

      // closing
      encryptor.processSegment(new byte[0]);
    }
  }

  @Test
  void shouldThrowExceptionIfSegmentAreOutOfOrder() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad);
        FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader())) {
      byte[] ciphertext1 = encryptor.processSegment(new byte[8]);
      byte[] ciphertext2 = encryptor.processSegment(new byte[8]);
      encryptor.processSegment(new byte[4]);
      FloeException e =
          assertThrows(FloeException.class, () -> decryptor.processSegment(ciphertext2));
      assertInstanceOf(AEADBadTagException.class, e.getCause());
    }
  }

  @Test
  void shouldThrowExceptionIfLastSegmentIsNeverReadDecrypted() throws Exception {
    FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
    Floe floe = Floe.getInstance(parameterSpec);
    try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
      byte[] ciphertext1 = encryptor.processSegment(new byte[8]);
      byte[] ciphertext2 = encryptor.processSegment(new byte[4]);
      FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, encryptor.getHeader());
      decryptor.processSegment(ciphertext1);
      assertThrows(IllegalStateException.class, decryptor::close);
    }
  }
}
