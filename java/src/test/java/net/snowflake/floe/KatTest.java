package net.snowflake.floe;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class KatTest {
  private final SecretKey referenceKey = new SecretKeySpec(new byte[32], "AES");
  private final byte[] referenceAad = "This is AAD".getBytes(StandardCharsets.UTF_8);

  @ParameterizedTest
  @MethodSource("referenceParameters")
  void compareWithReferenceData(FloeParameterSpec parameterSpec, String fileNamePrefix) throws Exception {
    run(parameterSpec, fileNamePrefix);
  }

  private static Stream<Arguments> referenceParameters() {
    return Stream.of(
        Arguments.of(
            new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 64, 32),
            "reference_java_GCM256_IV256_64"
        ),
        Arguments.of(
            new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 4 * 1024, 32),
            "reference_java_GCM256_IV256_4K"
        ),
        Arguments.of(
            new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 1024 * 1024, 32),
            "reference_java_GCM256_IV256_1M"
        ),
        Arguments.of(
            new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32, 4, 1L << 40),
            "reference_java_rotation"
        )
    );
  }

  @ParameterizedTest
  @MethodSource("customParameters")
  void compareWithCustomData(FloeParameterSpec parameterSpec, String fileNamePrefix) throws Exception {
    run(parameterSpec, fileNamePrefix);
  }

  @ParameterizedTest
  @MethodSource("customParameters")
  @Disabled
  void generateNewKats(FloeParameterSpec parameterSpec, String fileNamePrefix) throws Exception {
    createKatFromPlaintext(parameterSpec, fileNamePrefix);
  }

  private static Stream<Arguments> customParameters() {
    return Stream.of(
        Arguments.of(
            new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 64, 32),
            "public_java_GCM256_IV256_64"
        ),
        Arguments.of(
            new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 4 * 1024, 32),
            "public_java_GCM256_IV256_4K"
        ),
        Arguments.of(
            new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 1024 * 1024, 32),
            "public_java_GCM256_IV256_1M"
        ),
        Arguments.of(
            new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 40, 32, 4, 1L << 40),
            "public_java_rotation"
        )
    );
  }

  private void run(FloeParameterSpec parameterSpec, String fileNamePrefix) throws Exception {
    byte[] expectedPlaintext = readFile(fileNamePrefix + "_pt.txt");
    byte[] ciphertext = readFile(fileNamePrefix + "_ct.txt");

    Floe floe = Floe.getInstance(parameterSpec);

    ByteBuffer ciphertextBuffer = ByteBuffer.wrap(ciphertext);
    byte[] header = new byte[parameterSpec.getHeaderSize()];
    ciphertextBuffer.get(header);

    try (FloeDecryptor decryptor = floe.createDecryptor(referenceKey, referenceAad, header)) {
      byte[] ciphertextSegment = new byte[parameterSpec.getEncryptedSegmentLength()];
      ByteArrayOutputStream plaintextStream = new ByteArrayOutputStream();
      while (ciphertextBuffer.hasRemaining()) {
        if (ciphertextBuffer.remaining() < ciphertextSegment.length) {
          ciphertextSegment = new byte[ciphertextBuffer.remaining()];
        }
        ciphertextBuffer.get(ciphertextSegment);
        byte[] plaintextSegment = decryptor.processSegment(ciphertextSegment);
        plaintextStream.write(plaintextSegment);
      }
      byte[] plaintext = plaintextStream.toByteArray();
      assertArrayEquals(expectedPlaintext, plaintext);
    }
  }

  private void createKatFromPlaintext(FloeParameterSpec parameterSpec, String fileNamePrefix) throws Exception {
    byte[] plaintext = readFile(fileNamePrefix + "_pt.txt");
    String ciphertextFile = fileNamePrefix + "_ct.txt";

    Floe floe = Floe.getInstance(parameterSpec);

    ByteBuffer plaintextBuffer = ByteBuffer.wrap(plaintext);

    try (FloeEncryptor encryptor = floe.createEncryptor(referenceKey, referenceAad)) {
      try (FileOutputStream ciphertextStream = new FileOutputStream(ciphertextFile)) {
        ciphertextStream.write(byteArrayToHex(encryptor.getHeader()).getBytes(StandardCharsets.UTF_8));
        while(plaintextBuffer.hasRemaining()) {
          byte[] plaintextSegment = new byte[plaintextBuffer.remaining()];
          plaintextBuffer.get(plaintextSegment);
          byte[] ciphertextSegment = encryptor.processSegment(plaintextSegment);
          ciphertextStream.write(byteArrayToHex(ciphertextSegment).getBytes(StandardCharsets.UTF_8));
        }
      }
    }
  }
  
  private static byte[] readFile(String fileName) throws Exception {
    String hexFileContent = IOUtils.toString(KatTest.class.getClassLoader().getResource(fileName)).trim();
    return Hex.decodeHex(hexFileContent);
  }

  private static String byteArrayToHex(byte[] a) {
    StringBuilder sb = new StringBuilder(a.length * 2);
    for(byte b: a)
      sb.append(String.format("%02x", b));
    return sb.toString();
  }
}
