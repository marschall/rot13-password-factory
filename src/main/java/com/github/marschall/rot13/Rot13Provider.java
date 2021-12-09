package com.github.marschall.rot13;

import java.security.Provider;
import java.util.List;
import java.util.Map;

/**
 * Provider for rot-13 password implementation.
 */
public class Rot13Provider extends Provider {

  private static Rot13Provider INSTANCE = new Rot13Provider();

  private static final String PASSWORD_FACTORY_TYPE = "PasswordFactory";

  /**
   * Default constructor called by JCE.
   */
  public Rot13Provider() {
    super("Rot13Provider", "1.0", "ROT-13 Password Provider");
    putService(new Service(this, PASSWORD_FACTORY_TYPE, Rot13Password.ALGORITHM_ROT_13,
        Rot13PasswordFactory.class.getName(), List.of(), Map.of()));
  }

  /**
   * Get the password implementations provider instance.
   *
   * @return the password implementations provider instance
   */
  public static Rot13Provider getInstance() {
    return INSTANCE;
  }

}
