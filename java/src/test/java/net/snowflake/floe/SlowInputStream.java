package net.snowflake.floe;

import java.io.IOException;
import java.io.InputStream;

class SlowInputStream extends InputStream {
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
