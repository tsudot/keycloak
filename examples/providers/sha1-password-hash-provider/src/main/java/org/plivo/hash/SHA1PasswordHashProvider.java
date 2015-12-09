package org.plivo.hash;

import org.keycloak.Config;
import org.keycloak.hash.PasswordHashProvider;
import org.keycloak.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserCredentialValueModel;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.lang.StringBuilder;


/**
 * @author <a href="mailto:me@tsudot.com">Kunal Kerkar</a>
 */
public class SHA1PasswordHashProvider implements PasswordHashProviderFactory, PasswordHashProvider {

    public static final String ID = "sha1";
    private static final String SHA1_ALGORITHM = "SHA1";

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }

    private byte[] getSalt() {
        byte[] buffer = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }

    public UserCredentialValueModel encode(String rawPassword, int iterations) {
        byte[] salt = getSalt();
        String encodedPassword = encode(rawPassword, iterations, salt);

        UserCredentialValueModel credentials = new UserCredentialValueModel();
        credentials.setAlgorithm(ID);
        credentials.setType(UserCredentialModel.PASSWORD);
        credentials.setSalt(salt);
        credentials.setHashIterations(iterations);
        credentials.setValue(encodedPassword);
        return credentials;
    }

    public String encode(String rawPassword, int iterations, byte[] salt) {
        MessageDigest messageDigest;
        StringBuilder buffer = new StringBuilder(64);

        try {
            messageDigest = MessageDigest.getInstance(SHA1_ALGORITHM);

            byte[] p = rawPassword.getBytes();
            byte[] c = new byte[p.length + salt.length];
            System.arraycopy(salt, 0, c, 0, salt.length);
            System.arraycopy(p, 0, c, salt.length, p.length);


            byte[] digest = messageDigest.digest(c);

            for (int i=0; i < digest.length; i++) {
                int d=digest[i] & 0xFF;
                if (d < 0x10) {
                    buffer.append('0');
                }
                buffer.append(Integer.toHexString(d));
            }

        } catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException("SHA1 algorithm not found");
        }

        return buffer.toString();
    }

    public boolean verify(String rawPassword, UserCredentialValueModel credential) {
        return encode(rawPassword, credential.getHashIterations(), credential.getSalt()).equals(credential.getValue());
    }
}
