package net.snowflake.floe;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class FloeE2ETest {
  private static final SecureRandom random = new SecureRandom();
  private static final SecretKey secretKey = new SecretKeySpec(new byte[32], "AES");
  private static final byte[] aad = new byte[32];

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
    runForVariousPlaintextSizes(FloeParameterSpec.GCM256_SHA384_4K);
  }

  @Test
  void runFor1MB() throws Exception {
    runForVariousPlaintextSizes(FloeParameterSpec.GCM256_SHA384_1M);
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
        byte[] ciphertext;
        int readBytes = plaintextInputStream.read(plaintextSegment);
        if (readBytes == -1) {
          ciphertext = encryptor.processSegment(new byte[0]); // terminal segment
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

  @ParameterizedTest
  @MethodSource("slowStreamParams")
  void testSlowStream(int plaintextSize, FloeParameterSpec parameterSpec) throws Exception {
    Floe floe = Floe.getInstance(parameterSpec);

    // ENCRYPTION PHASE
    byte[] plaintext = new byte[plaintextSize];
    random.nextBytes(plaintext);
    InputStream plaintextInputStream = new SlowInputStream(7, new ByteArrayInputStream(plaintext));

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
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

    byte[] ciphertext = baos.toByteArray();
    InputStream ciphertextInputStream = new SlowInputStream(9, new ByteArrayInputStream(ciphertext));
    baos = new ByteArrayOutputStream();

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
    assertArrayEquals(plaintext, baos.toByteArray());
  }

  private static Stream<Arguments> slowStreamParams() {
    return Stream.of(
        Arguments.of(50, FloeParameterSpec.GCM256_SHA384_4K),
        Arguments.of(FloeParameterSpec.GCM256_SHA384_4K.getPlainTextSegmentLength(), FloeParameterSpec.GCM256_SHA384_1M),
        Arguments.of(FloeParameterSpec.GCM256_SHA384_4K.getPlainTextSegmentLength() + 5, FloeParameterSpec.GCM256_SHA384_4K),
        Arguments.of(FloeParameterSpec.GCM256_SHA384_4K.getPlainTextSegmentLength() * 2, FloeParameterSpec.GCM256_SHA384_4K),
        Arguments.of(FloeParameterSpec.GCM256_SHA384_4K.getPlainTextSegmentLength() * 2 + 1, FloeParameterSpec.GCM256_SHA384_4K)
    );
  }

  private static class SlowInputStream extends InputStream {
    private final int numberOfBytes;
    private final InputStream delegate;

    public SlowInputStream(int numberOfBytes, InputStream delegate) {
      this.numberOfBytes = numberOfBytes;
      this.delegate = delegate;
    }

    @Override
    public int read() throws IOException {
      return delegate.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      return delegate.read(b, off, Math.min(len, numberOfBytes));
    }
  }
}
