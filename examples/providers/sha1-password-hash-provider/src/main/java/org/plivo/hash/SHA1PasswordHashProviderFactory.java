package org.plivo.hash;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.hash.PasswordHashProvider;
import org.keycloak.hash.PasswordHashProviderFactory;

/**
 * @author <a href="mailto:me@tsudot.com">Kunal Kerkar</a>
 */
public class SHA1PasswordHashProviderFactory implements PasswordHashProviderFactory {

    @Override
    public PasswordHashProvider create(KeycloakSession session) {  
        return new SHA1PasswordHashProvider();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return "sha1";
    }

    @Override
    public void close() {
    }

}

