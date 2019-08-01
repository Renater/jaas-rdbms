// $Id: DBLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package com.tagish.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Map;
import java.util.Vector;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple database based authentication module.
 *
 * @author Andy Armstrong, <A HREF="mailto:andy@tagish.com">andy@tagish.com</A>
 * @version 1.0.3
 */
public class DBLogin extends SimpleLogin {

	private final Logger logger = LoggerFactory.getLogger(DBLogin.class);

	protected String dbDriver;
	protected String dbURL;
	protected String dbUser;
	protected String dbPassword;
	protected String userTable;
	protected String userColumn;
	protected String passColumn;
	protected String where;
	protected String algo;

	protected synchronized Vector validateUser(String username, char password[]) throws LoginException {
		ResultSet rsu = null;
		Connection con = null;
		PreparedStatement psu = null;

		try {
			Class.forName(dbDriver);
			if (dbUser != null) {
				con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
			} else {
				con = DriverManager.getConnection(dbURL);
			}

			psu = con.prepareStatement(
					"SELECT " + passColumn + " FROM " + userTable + " WHERE lower(" + userColumn + ")=?" + where);

			/* Set the username to the statement */
			psu.setString(1, username.toLowerCase());
			rsu = psu.executeQuery();
			if (!rsu.next()) {
				logger.warn("Unknown user {}", username);
				throw new FailedLoginException("Invalid credentials");
			}
			String upwd = rsu.getString(1);
			String tpwd = new String(password);

			logger.debug("Tyring to authenticate {} with password {} / Hash = {} / Algo = {}", username, tpwd, upwd,
					algo);

			boolean passwordOk = false;
			/* Check the password */
			switch (algo) {
			case "SHA1":
				passwordOk = matchesSHA1Password(tpwd, upwd);
				break;
			case "BCRYPT":
				passwordOk = BCrypt.checkpw(tpwd, upwd);
				break;
			default:
				logger.error("Unknown algo {}", algo);
				throw new FailedLoginException("Unknown algo");
			}

			if (!passwordOk) {
				logger.warn("Invalid password for user {}", username);
				throw new FailedLoginException("Invalid credentials");
			}

			Vector p = new Vector();
			p.add(new TypedPrincipal(username, TypedPrincipal.USER));
			return p;
		} catch (Exception e) {
			logger.error("Error", e);
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		} finally {
			try {
				if (rsu != null) {
					rsu.close();
				}
				if (psu != null) {
					psu.close();
				}
				if (con != null) {
					con.close();
				}
			} catch (Exception e) {
			}
		}
	}

	public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
		super.initialize(subject, callbackHandler, sharedState, options);

		dbDriver = getOption("dbDriver", null);
		if (dbDriver == null) {
			throw new Error("No database driver named (dbDriver=?)");
		}
		dbURL = getOption("dbURL", null);
		if (dbURL == null) {
			throw new Error("No database URL specified (dbURL=?)");
		}
		dbUser = getOption("dbUser", null);
		dbPassword = getOption("dbPassword", null);
		if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null))
			throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");

		userTable = getOption("userTable", "User");
		userColumn = getOption("userColumn", "user_name");
		passColumn = getOption("passColumn", "user_passwd");
		where = getOption("where", "");
		if (null != where && where.length() > 0)
			where = " AND " + where;
		else
			where = "";

		algo = getOption("algo", "SHA1");
	}

	/**
	 * Hashing the clear password to obtain a SHA1 digest
	 * 
	 * @param password The clearText password
	 * @return
	 * @throws FailedLoginException
	 */
	private static String hashingPasswordSHA1(String clearTextPassword) throws FailedLoginException {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			throw new FailedLoginException("Unknown algo SHA-1 (" + e.getMessage() + ")");
		} // catch

		if (md != null) {
			md.update(clearTextPassword.getBytes());
			return HexString.bufferToHex(md.digest()).toLowerCase();
		}
		return "";
	}

	/**
	 * Matches the clear password with the SHA1 password of the member
	 * 
	 * @param password
	 * @return boolean
	 */
	private boolean matchesSHA1Password(String password, String sha1Password) {
		try {
			String hashPasswd = hashingPasswordSHA1(password);
			return null != hashPasswd && hashPasswd.length() > 0 && password != null && password.length() > 0
					&& hashPasswd.toLowerCase().equals(sha1Password.toLowerCase());
		} catch (Exception e) {
			return false;
		}
	}
}
