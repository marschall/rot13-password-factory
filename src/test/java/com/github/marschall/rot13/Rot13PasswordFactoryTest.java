package com.github.marschall.rot13;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.DigestPasswordSpec;

class Rot13PasswordFactoryTest {

  @Test
  void verify() throws GeneralSecurityException {
    PasswordFactory passwordFactory = PasswordFactory.getInstance(Rot13Password.ALGORITHM_ROT_13);
    assertNotNull(passwordFactory);

    DigestPasswordSpec keySpec = new DigestPasswordSpec("sa", "narnia",
        "Jul qvq gur puvpxra pebff gur ebnq?".getBytes());
    Password password = passwordFactory.generatePassword(keySpec);
    assertTrue(passwordFactory.verify(password, "Why did the chicken cross the road?".toCharArray()));
  }

}
