package org.keycloak.hash;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * @author <a href="mailto:me@tsudot.com">Kunal Kerkar</a>
 */
public class SHAPasswordHashProviderFactory implements PasswordHashProviderFactory {

    private int strength;

    @Override
    public PasswordHashProvider create(KeycloakSession session) {  
        return new SHAPasswordHashProvider(strength);
    }

    @Override
    public void init(Config.Scope config) {
        strength = config.getInt("strength");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return "sha";
    }

    @Override
    public void close() {
    }

}

