package de.gghub.keycloak.steam;

import java.util.List;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

public final class SteamIdentityProviderFactory extends AbstractIdentityProviderFactory<SteamIdentityProvider> {
    public static final String ID = "ggh-steam-openid2";
    @Override public String getId() { return ID; }
    @Override public String getName() { return "Steam OpenID 2.0 (GGH)"; }
    @Override public SteamIdentityProvider create(KeycloakSession session, IdentityProviderModel config) { return new SteamIdentityProvider(session,config); }
    @Override public IdentityProviderModel createConfig() { return new IdentityProviderModel(); }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}
