package org.keycloak.models.utils;

import org.keycloak.common.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * <p>
 * Password that uses SHA to encode passwords. You can always change the SHA strength by specifying a valid
 * integer when creating a new instance.
 * </p>
 * <p>Passwords are returned with a Base64 encoding.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Silva</a>
 *
 */
public class SHAPasswordEncoder {

    private int strength;

    public SHAPasswordEncoder(int strength) {
        this.strength = strength;
    }

    public String encode(String rawPassword, byte[] salt) {
        MessageDigest messageDigest = getMessageDigest();

        String encodedPassword = null;
        byte[] rawPasswordByte;

        try {
            rawPasswordByte = rawPassword.getBytes("UTF-8");
            byte[] c = new byte[salt.length + rawPasswordByte.length];
            System.arraycopy(salt, 0, c, 0, salt.length);
            System.arraycopy(rawPasswordByte, 0, c, salt.length, rawPasswordByte.length);

            byte[] digest = messageDigest.digest(c);
            encodedPassword = Base64.encodeBytes(digest);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Credential could not be encoded");
        }

        return encodedPassword;
    }

    public boolean verify(String rawPassword, String encodedPassword, byte[] salt) {
        return encode(rawPassword, salt).equals(encodedPassword);
    }

    protected final MessageDigest getMessageDigest() throws IllegalArgumentException {
        String algorithm = "SHA-" + this.strength;

        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("invalid credential encoding algorithm");
        }
    }

    public int getStrength() {
        return this.strength;
    }
}
