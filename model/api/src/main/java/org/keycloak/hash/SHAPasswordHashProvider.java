package org.keycloak.hash;

import org.keycloak.models.utils.SHAPasswordEncoder;

/**
 * @author <a href="mailto:me@tsudot.com">Kunal Kerkar</a>
 */
public class SHAPasswordHashProvider implements PasswordHashProvider {

    private final String algorithm;
    private final int strength;

    public SHAPasswordHashProvider(int strength) {
        this.algorithm = "sha";
        this.strength = strength;
    }

    public String encode(String rawPassword, byte[] salt) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA1"); 
        SHAPasswordEncoder encoder = new SHAPasswordEncoder(strength);
        return encoder.encode(rawPassword, salt);
    }

    public boolean verify(String rawPassword, String encodedPassword, byte[] salt) {
        SHAPasswordEncoder encoder = new SHAPasswordEncoder(strength);
        return encoder.verify(rawPassword, encodedPassword, salt);
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public void close() {
    }

}
