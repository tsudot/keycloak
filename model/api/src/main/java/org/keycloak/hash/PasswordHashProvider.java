package org.keycloak.hash;

import org.keycloak.provider.Provider;

/**
 * @author <a href="mailto:me@tsudot.com">Kunal Kerkar</a>
 */
public interface PasswordHashProvider extends Provider {

    String encode(String rawPassword, byte[] salt);

    boolean verify(String rawPassword, String encodedPassword, byte[] salt);

    String getAlgorithm();

}
