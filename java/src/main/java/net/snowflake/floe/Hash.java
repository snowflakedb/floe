package net.snowflake.floe;

public enum Hash {
  SHA384((byte) 0, "HmacSHA384", 48);

  private byte id;
  private final String jceHmacName;
  private final int length;

  Hash(byte id, String jceHmacName, int length) {
    this.id = id;
    this.jceHmacName = jceHmacName;
    this.length = length;
  }

  public byte getId() {
    return id;
  }

  public String getJceHmacName() {
    return jceHmacName;
  }

  public int getLength() {
    return length;
  }
}
