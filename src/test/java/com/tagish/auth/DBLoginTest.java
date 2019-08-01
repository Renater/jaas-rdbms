package com.tagish.auth;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

public class DBLoginTest extends Assertions {

	@Test
	public void test() {
		String bcrypt = "$2a$10$nyYrjbfkL86M5.oLqoQwye3BO/SeTHPyGQRZOxPvfJISrrixVc3rK";
		String password = "Password1234!";

		System.out.println(BCrypt.hashpw(password, BCrypt.gensalt()));

		assertThat(BCrypt.checkpw(password, bcrypt)).isTrue();

		assertThat(BCrypt.checkpw(password + " ", bcrypt)).isFalse();
	}

}
