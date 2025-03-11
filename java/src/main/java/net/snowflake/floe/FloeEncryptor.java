package net.snowflake.floe;

/**
 * FLOE encryptor. Implementations of these classes are not thread safe.
 */
public interface FloeEncryptor extends AutoCloseable {
  /**
   * Processes given plaintext to ciphertext.
   * This function is to be used only with non terminal segments.
   * Plaintext must be of the size specified by {@link FloeParameterSpec#getPlainTextSegmentLength()}.
   *
   * @param plaintext plaintext to be encrypted.
   * @return ciphertext.
   */
  byte[] processSegment(byte[] plaintext);

  /**
   * Processes given ciphertext to plaintext.
   * This function is to be used only with terminal segments.
   * This function needs to be called exactly once.
   * Segment may be empty or at most {@link FloeParameterSpec#getPlainTextSegmentLength()} long.
   *
   * @param plaintext plaintext to be encrypted.
   * @return ciphertext.
   */
  byte[] processLastSegment(byte[] plaintext);

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
