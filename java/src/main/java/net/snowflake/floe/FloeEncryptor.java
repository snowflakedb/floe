package net.snowflake.floe;

/**
 * FLOE encryptor. Implementations of these classes are not thread safe.
 */
public interface FloeEncryptor extends AutoCloseable {
  /**
   * Processes given plaintext to ciphertext.
   * Plaintext must be of the size specified by {@link FloeParameterSpec#getPlainTextSegmentLength()} or less.
   * If segment size is equal to {@link FloeParameterSpec#getPlainTextSegmentLength()}, non terminal segment is assumed.
   * If segment size is lower than {@link FloeParameterSpec#getPlainTextSegmentLength()}, it is assumed to be terminal.
   * Empty segment is also accepted as the terminal segment.
   *
   * @param plaintext plaintext to be encrypted.
   * @return ciphertext.
   */
  byte[] processSegment(byte[] plaintext);

  /**
   * Processes given plaintext to ciphertext.
   * Plaintext must be of the size specified by {@link FloeParameterSpec#getPlainTextSegmentLength()} or less.
   * If segment size is equal to {@link FloeParameterSpec#getPlainTextSegmentLength()}, non terminal segment is assumed.
   * If segment size is lower than {@link FloeParameterSpec#getPlainTextSegmentLength()}, it is assumed to be terminal.
   * Empty segment is also accepted as the terminal segment.
   *
   * @param plaintext plaintext to be encrypted.
   * @param offset index of the first byte to process.
   * @param length how many bytes should be processed.
   * @return ciphertext.
   */
  byte[] processSegment(byte[] plaintext, int offset, int length);

  /**
   * Returns header for this FLOE instance, that is required for decryption.
   *
   * @return header for this FLOE instance.
   */
  byte[] getHeader();

  /**
   * Returns information if last segment was already processed.
   *
   * @return if last segment was already processed.
   */
  boolean isClosed();
}
