package de.gghub.keycloak.steam;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

public final class SteamProfileAttributeMapper extends AbstractJsonUserAttributeMapper {
    @Override public String getId() { return "ggh-steam-profile-attribute"; }
    @Override public String getDisplayType() { return "Steam Profile Attribute Importer"; }
    @Override public String[] getCompatibleProviders() { return new String[]{SteamIdentityProviderFactory.ID}; }
    @Override public String getHelpText() { return "Import the verified Steam ID: source steam_id (or id), target a custom profile attribute such as steam_id or steamId. FORCE updates on subsequent Steam logins. Copied attributes remain after unlinking."; }
}
