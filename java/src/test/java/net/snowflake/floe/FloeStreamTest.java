package net.snowflake.floe;

import net.snowflake.floe.stream.FloeDecryptingInputStream;
import net.snowflake.floe.stream.FloeEncryptingInputStream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class FloeStreamTest {
  private final SecretKey secretKey = new SecretKeySpec(new byte[32], "FLOE");
  private final byte[] aad = "test AAD".getBytes(StandardCharsets.UTF_8);

  abstract class AbstractStreamTest {
    protected abstract boolean headerInStream();

    @ParameterizedTest
    @ValueSource(ints = {0, 3})
    void shouldEncryptAndDecryptWithHeaderInStreamWithSimpleRead(int lastSegmentLength) throws Exception {
      FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
      byte[] plaintextBytes = new byte[2 * parameterSpec.getPlainTextSegmentLength() + lastSegmentLength];
      runWithSimpleRead(plaintextBytes, parameterSpec);
    }

    @Test
    void shouldEncryptEmptyFileWithSimpleRead() throws Exception {
      FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
      byte[] plaintextBytes = new byte[0];
      runWithSimpleRead(plaintextBytes, parameterSpec);
    }

    private void runWithSimpleRead(byte[] plaintextBytes, FloeParameterSpec parameterSpec) throws IOException {
      FloeEncryptingInputStream encryptingInputStream = new FloeEncryptingInputStream(new ByteArrayInputStream(plaintextBytes), parameterSpec, secretKey, aad, headerInStream());
      ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();

      int b;
      while ((b = encryptingInputStream.read()) != -1) {
        ciphertextOutputStream.write(b);
      }

      byte[] ciphertextBytes = ciphertextOutputStream.toByteArray();
      FloeDecryptingInputStream decryptingInputStream = new FloeDecryptingInputStream(new ByteArrayInputStream(ciphertextBytes), parameterSpec, secretKey, aad, headerInStream() ? null : encryptingInputStream.getHeader());
      ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();

      while ((b = decryptingInputStream.read()) != -1) {
        resultOutputStream.write(b);
      }
      assertArrayEquals(plaintextBytes, resultOutputStream.toByteArray());
    }

    @ParameterizedTest
    @CsvSource({
        "0, 40",
        "3, 40",
        "0, 20",
        "3, 20",
        "0, 1024",
        "3, 1024",
        "0, 7",
        "3, 7",
        "0, 77",
        "3, 77",
        "0, 17",
        "3, 17"
    })
    void shouldEncryptAndDecryptWithBufferedRead(int lastSegmentLength, int bufferSize) throws Exception {
      FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
      byte[] plaintextBytes = new byte[2 * parameterSpec.getPlainTextSegmentLength() + lastSegmentLength];
      runWithBufferedRead(plaintextBytes, parameterSpec, bufferSize);
    }

    @ParameterizedTest
    @ValueSource(ints = {40})
    void shouldEncryptEmptyFileWithBufferedRead(int bufferSize) throws Exception {
      FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
      byte[] plaintextBytes = new byte[0];
      runWithBufferedRead(plaintextBytes, parameterSpec, bufferSize);
    }

    private void runWithBufferedRead(byte[] plaintextBytes, FloeParameterSpec parameterSpec, int bufferSize) throws IOException {
      FloeEncryptingInputStream encryptingInputStream = new FloeEncryptingInputStream(new ByteArrayInputStream(plaintextBytes), parameterSpec, secretKey, aad, headerInStream());
      ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();

      int read;
      byte[] buffer = new byte[bufferSize];
      while ((read = encryptingInputStream.read(buffer, 0, buffer.length)) != -1) {
        ciphertextOutputStream.write(buffer, 0, read);
      }

      byte[] ciphertextBytes = ciphertextOutputStream.toByteArray();
      FloeDecryptingInputStream decryptingInputStream = new FloeDecryptingInputStream(new ByteArrayInputStream(ciphertextBytes), parameterSpec, secretKey, aad, headerInStream() ? null : encryptingInputStream.getHeader());
      ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();

      while ((read = decryptingInputStream.read(buffer, 0, buffer.length)) != -1) {
        resultOutputStream.write(buffer, 0, read);
      }
      assertArrayEquals(plaintextBytes, resultOutputStream.toByteArray());
    }

    @ParameterizedTest
    @CsvSource(value = {
        "0, 4",
        "0, 8",
        "0, 17",
        "0, 1024",
        "1, 4",
        "1, 8",
        "1, 17",
        "1, 1024",
    })
    void shouldCorrectlyMixSimpleAndBufferedReads(int lastSegmentLength, int bufferSize) throws Exception {
      FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
      byte[] plaintextBytes = new byte[2 * parameterSpec.getPlainTextSegmentLength() + lastSegmentLength];
      FloeEncryptingInputStream encryptingInputStream = new FloeEncryptingInputStream(new ByteArrayInputStream(plaintextBytes), parameterSpec, secretKey, aad, headerInStream());
      ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();
      while (true) {
        byte b = (byte) encryptingInputStream.read();
        if (encryptingInputStream.isClosed()) {
          break;
        }
        ciphertextOutputStream.write(b);
        byte[] buf = new byte[bufferSize];
        int read = encryptingInputStream.read(buf);
        if (read == -1) {
          break;
        }
        ciphertextOutputStream.write(buf, 0, read);
      }
      byte[] ciphertextBytes = ciphertextOutputStream.toByteArray();

      ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();

      FloeDecryptingInputStream decryptingInputStream = new FloeDecryptingInputStream(new ByteArrayInputStream(ciphertextBytes), parameterSpec, secretKey, aad, headerInStream() ? null : encryptingInputStream.getHeader());
      while (true) {
        byte b = (byte) decryptingInputStream.read();
        if (decryptingInputStream.isClosed()) {
          break;
        }
        resultOutputStream.write(b);
        byte[] buf = new byte[bufferSize];
        int read = decryptingInputStream.read(buf);
        if (read == -1) {
          break;
        }
        resultOutputStream.write(buf, 0, read);
      }
      assertArrayEquals(plaintextBytes, resultOutputStream.toByteArray());
    }

    @ParameterizedTest
    @CsvSource(value = {
        "0, 4",
        "0, 8",
        "0, 1024",
        "1, 4",
        "1, 8",
        "1, 17",
        "1, 1024",
    })
    void shouldCorrectlyMixSimpleAndBufferedReadsWithNonZeroOffset(int lastSegmentLength, int bufferSize) throws Exception {
      FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
      byte[] plaintextBytes = new byte[2 * parameterSpec.getPlainTextSegmentLength() + lastSegmentLength];
      FloeEncryptingInputStream encryptingInputStream = new FloeEncryptingInputStream(new ByteArrayInputStream(plaintextBytes), parameterSpec, secretKey, aad, headerInStream());
      ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();
      while (true) {
        if (encryptingInputStream.isClosed()) {
          break;
        }
        byte b = (byte) encryptingInputStream.read();
        ciphertextOutputStream.write(b);
        if (encryptingInputStream.isClosed()) {
          break;
        }
        byte[] buf = new byte[bufferSize];
        int read = encryptingInputStream.read(buf, 2, bufferSize - 2);
        if (read == -1) {
          break;
        }
        ciphertextOutputStream.write(buf, 2, read);
      }
      byte[] ciphertextBytes = ciphertextOutputStream.toByteArray();

      ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();

      FloeDecryptingInputStream decryptingInputStream = new FloeDecryptingInputStream(new ByteArrayInputStream(ciphertextBytes), parameterSpec, secretKey, aad, headerInStream() ? null : encryptingInputStream.getHeader());
      while (true) {
        if (decryptingInputStream.isClosed()) {
          break;
        }
        byte b = (byte) decryptingInputStream.read();
        resultOutputStream.write(b);
        if (decryptingInputStream.isClosed()) {
          break;
        }
        byte[] buf = new byte[bufferSize];
        int read = decryptingInputStream.read(buf, 2, bufferSize - 2);
        if (read == -1) {
          break;
        }
        resultOutputStream.write(buf, 2, read);
      }
      assertArrayEquals(plaintextBytes, resultOutputStream.toByteArray());
    }

    @ParameterizedTest
    @CsvSource({
        "0, 7, 40",
        "3, 7, 40",
        "0, 5, 20",
        "3, 9, 1024",
        "0, 11, 77",
        "3, 13, 17"
    })
    void shouldEncryptAndDecryptWithSlowInputStream(int lastSegmentLength, int slowReadSize, int bufferSize) throws Exception {
      FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
      byte[] plaintextBytes = new byte[2 * parameterSpec.getPlainTextSegmentLength() + lastSegmentLength];
      FloeEncryptingInputStream encryptingInputStream = new FloeEncryptingInputStream(new SlowInputStream(slowReadSize, new ByteArrayInputStream(plaintextBytes)), parameterSpec, secretKey, aad, headerInStream());
      ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();

      int read;
      byte[] buffer = new byte[bufferSize];
      while ((read = encryptingInputStream.read(buffer, 0, buffer.length)) != -1) {
        ciphertextOutputStream.write(buffer, 0, read);
      }

      byte[] ciphertextBytes = ciphertextOutputStream.toByteArray();
      FloeDecryptingInputStream decryptingInputStream = new FloeDecryptingInputStream(new SlowInputStream(slowReadSize, new ByteArrayInputStream(ciphertextBytes)), parameterSpec, secretKey, aad, headerInStream() ? null : encryptingInputStream.getHeader());
      ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();

      while ((read = decryptingInputStream.read(buffer, 0, buffer.length)) != -1) {
        resultOutputStream.write(buffer, 0, read);
      }
      assertArrayEquals(plaintextBytes, resultOutputStream.toByteArray());
    }

    @ParameterizedTest
    @ValueSource(ints = {5, 7, 11})
    void shouldEncryptAndDecryptEmptyFileWithSlowInputStream(int slowReadSize) throws Exception {
      FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
      byte[] plaintextBytes = new byte[0];
      FloeEncryptingInputStream encryptingInputStream = new FloeEncryptingInputStream(new SlowInputStream(slowReadSize, new ByteArrayInputStream(plaintextBytes)), parameterSpec, secretKey, aad, headerInStream());
      ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();

      int read;
      byte[] buffer = new byte[40];
      while ((read = encryptingInputStream.read(buffer, 0, buffer.length)) != -1) {
        ciphertextOutputStream.write(buffer, 0, read);
      }

      byte[] ciphertextBytes = ciphertextOutputStream.toByteArray();
      FloeDecryptingInputStream decryptingInputStream = new FloeDecryptingInputStream(new SlowInputStream(slowReadSize, new ByteArrayInputStream(ciphertextBytes)), parameterSpec, secretKey, aad, headerInStream() ? null : encryptingInputStream.getHeader());
      ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();

      while ((read = decryptingInputStream.read(buffer, 0, buffer.length)) != -1) {
        resultOutputStream.write(buffer, 0, read);
      }
      assertArrayEquals(plaintextBytes, resultOutputStream.toByteArray());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 3})
    void shouldEncryptWithStreamAndDecryptWithPlainFloe(int lastSegmentLength) throws Exception {
      FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
      byte[] plaintextBytes = new byte[2 * parameterSpec.getPlainTextSegmentLength() + lastSegmentLength];
      FloeEncryptingInputStream encryptingInputStream = new FloeEncryptingInputStream(new ByteArrayInputStream(plaintextBytes), parameterSpec, secretKey, aad, headerInStream());
      ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();

      int read;
      byte[] buffer = new byte[40];
      while ((read = encryptingInputStream.read(buffer, 0, buffer.length)) != -1) {
        ciphertextOutputStream.write(buffer, 0, read);
      }

      byte[] ciphertextBytes = ciphertextOutputStream.toByteArray();
      ByteArrayInputStream ciphertextInputStream = new ByteArrayInputStream(ciphertextBytes);
      ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();

      byte[] header;
      if (headerInStream()) {
        header = new byte[parameterSpec.getHeaderSize()];
        ciphertextInputStream.read(header);
      } else {
        header = encryptingInputStream.getHeader();
      }

      Floe floe = Floe.getInstance(parameterSpec);
      try (FloeDecryptor decryptor = floe.createDecryptor(secretKey, aad, header)) {
        byte[] ciphertextSegment = new byte[parameterSpec.getEncryptedSegmentLength()];
        do {
          int readBytes = ciphertextInputStream.read(ciphertextSegment);
          byte[] targetPlaintext = decryptor.processSegment(ciphertextSegment, 0, readBytes);
          resultOutputStream.write(targetPlaintext, 0, targetPlaintext.length);
        } while (!decryptor.isClosed());
      }
      assertArrayEquals(plaintextBytes, resultOutputStream.toByteArray());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 3})
    void shouldEncryptWithPlainFloeAndDecryptWithStream(int lastSegmentLength) throws Exception {
      FloeParameterSpec parameterSpec = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32);
      byte[] plaintextBytes = new byte[2 * parameterSpec.getPlainTextSegmentLength() + lastSegmentLength];
      ByteArrayInputStream plaintextInputStream = new ByteArrayInputStream(plaintextBytes);
      ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();

      Floe floe = Floe.getInstance(parameterSpec);
      byte[] header;
      try (FloeEncryptor encryptor = floe.createEncryptor(secretKey, aad)) {
        header = encryptor.getHeader();
        if (headerInStream()) {
          ciphertextOutputStream.write(header);
        }
        byte[] plaintextSegment = new byte[parameterSpec.getPlainTextSegmentLength()];
        do {
          byte[] ciphertext;
          int readBytes = plaintextInputStream.read(plaintextSegment);
          if (readBytes == -1) {
            ciphertext = encryptor.processSegment(new byte[0]);
          } else {
            ciphertext = encryptor.processSegment(plaintextSegment, 0, readBytes);
          }
          ciphertextOutputStream.write(ciphertext, 0, ciphertext.length);
        } while (!encryptor.isClosed());
      }

      byte[] ciphertextBytes = ciphertextOutputStream.toByteArray();
      FloeDecryptingInputStream decryptingInputStream = new FloeDecryptingInputStream(new ByteArrayInputStream(ciphertextBytes), parameterSpec, secretKey, aad, headerInStream() ? null : header);
      ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();

      int read;
      byte[] buffer = new byte[40];
      while ((read = decryptingInputStream.read(buffer, 0, buffer.length)) != -1) {
        resultOutputStream.write(buffer, 0, read);
      }
      assertArrayEquals(plaintextBytes, resultOutputStream.toByteArray());
    }
  }

  @Nested
  class HeaderInStreamTest extends AbstractStreamTest {
    @Override
    protected boolean headerInStream() {
      return true;
    }
  }

  @Nested
  class HeaderOutOfStreamTest extends AbstractStreamTest {
    @Override
    protected boolean headerInStream() {
      return false;
    }
  }
}
