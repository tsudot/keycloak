package org.keycloak.hash;

import static org.keycloak.models.utils.Pbkdf2PasswordEncoder.getSalt;

import org.keycloak.models.utils.Pbkdf2PasswordEncoder;

/**
 * @author <a href="mailto:me@tsudot.com">Kunal Kerkar</a>
 */
public class DefaultPasswordHashProvider implements PasswordHashProvider {

    private final String algorithm;
    private final int iterations;

    public DefaultPasswordHashProvider() {
        this.algorithm = "pbkdf2";
        this.iterations = 1;
    }

    public String encode(String rawPassword, byte[] salt) {
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder(salt);
        return encoder.encode(rawPassword);
    }

    public boolean verify(String rawPassword, String encodedPassword, byte[] salt) {
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder(salt);
        return encoder.verify(rawPassword, encodedPassword);
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public void close() {
    }

}
