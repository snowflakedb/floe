package net.snowflake.floe;

public enum Hash {
  SHA384((byte) 0, "HmacSHA384");

  private byte id;
  private final String jceHmacName;

  Hash(byte id, String jceHmacName) {
    this.id = id;
    this.jceHmacName = jceHmacName;
  }

  byte getId() {
    return id;
  }

  public String getJceHmacName() {
    return jceHmacName;
  }
}
