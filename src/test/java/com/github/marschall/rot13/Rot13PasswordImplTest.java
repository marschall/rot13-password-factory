package com.github.marschall.rot13;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class Rot13PasswordImplTest {

  static List<Arguments> parameters() {
    return List.of(
        Arguments.of("Why did the chicken cross the road?", "Jul qvq gur puvpxra pebff gur ebnq?"),
        Arguments.of("To get to the other side!", "Gb trg gb gur bgure fvqr!"));
  }

  @ParameterizedTest
  @MethodSource("parameters")
  void verify(String plain, String encrypted) {
    Rot13PasswordImpl password = new Rot13PasswordImpl(encrypted.toCharArray());

    assertTrue(password.verify(plain.toCharArray()));

    assertFalse(password.verify(plain.substring(0, plain.length() - 1).toCharArray()));
    assertFalse(password.verify(plain.concat("a").toCharArray()));
  }

}
