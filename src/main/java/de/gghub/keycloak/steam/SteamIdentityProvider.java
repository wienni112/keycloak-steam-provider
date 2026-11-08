package de.gghub.keycloak.steam;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.*;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.services.messages.Messages;

/** Steam OpenID 2.0 using modern Keycloak authentication-session callbacks. */
public final class SteamIdentityProvider extends AbstractIdentityProvider<IdentityProviderModel> {
    public SteamIdentityProvider(KeycloakSession session, IdentityProviderModel config) { super(session,config); }

    @Override public Response performLogin(AuthenticationRequest request) {
        String callback = request.getRedirectUri();
        URI uri = URI.create(callback);
        SteamAssertion.require("https".equals(uri.getScheme()) && uri.getHost() != null
            && uri.getUserInfo() == null && uri.getFragment() == null && uri.getQuery() == null,
            "Steam requires a public HTTPS Keycloak callback URL");
        String state = request.getState().getEncoded();
        String returnTo = UriBuilder.fromUri(callback).queryParam("state",state).build().toString();
        // Bind the exact return URL to this authentication attempt, with atomic single-use consumption.
        session.singleUseObjects().put(attemptKey(state),SteamAssertion.MAX_AGE,
            Map.of("returnTo",returnTo,"issuedAt",Long.toString(Instant.now().getEpochSecond())));
        String realm = UriBuilder.fromUri(callback).replacePath("/").replaceQuery(null).build().toString();
        URI login = UriBuilder.fromUri(SteamAssertion.ENDPOINT)
            .queryParam("openid.ns",SteamAssertion.NS).queryParam("openid.mode","checkid_setup")
            .queryParam("openid.return_to",returnTo).queryParam("openid.realm",realm)
            .queryParam("openid.identity",SteamAssertion.NS + "/identifier_select")
            .queryParam("openid.claimed_id",SteamAssertion.NS + "/identifier_select").build();
        return Response.seeOther(login).build();
    }

    private String attemptKey(String state) {
        return "ggh-steam-attempt:" + session.getContext().getRealm().getId() + ":" + getConfig().getAlias() + ":" + digest(state);
    }
    static String digest(String text) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    @Override public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(this,callback);
    }
    @Override public Response retrieveToken(KeycloakSession s, FederatedIdentityModel identity) { return Response.noContent().build(); }
    @Override public Response retrieveToken(KeycloakSession s, FederatedIdentityModel identity, UserSessionModel us, UserModel user) { return Response.noContent().build(); }

    @jakarta.ws.rs.ext.Provider
    @jakarta.enterprise.inject.Vetoed
    public static final class Endpoint {
        private final SteamIdentityProvider provider;
        private final KeycloakSession session;
        private final AuthenticationCallback callback;
        Endpoint(SteamIdentityProvider provider, AuthenticationCallback callback) {
            this.provider=provider;this.session=provider.session;this.callback=callback;
        }
        private IdentityProviderModel getConfig() { return provider.getConfig(); }
        @GET public Response respond() {
            try { return handle(SteamAssertion.flatten(session.getContext().getUri().getQueryParameters())); }
            catch (IllegalArgumentException e) { return callback.error(getConfig(),Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR); }
        }
        Response handle(Map<String,String> params) {
            try {
                String state = params.get("state");
                SteamAssertion.require(state != null && !state.isBlank(),"Missing state");
                var auth = callback.getAndVerifyAuthenticationSession(state);
                SteamAssertion.require(auth != null,"Missing authentication session");
                session.getContext().setAuthenticationSession(auth);
                var attempt = session.singleUseObjects().remove(provider.attemptKey(state));
                SteamAssertion.require(attempt != null,"Expired or already used authentication attempt");
                long age = Instant.now().getEpochSecond() - Long.parseLong(attempt.get("issuedAt"));
                SteamAssertion.require(age >= 0 && age <= SteamAssertion.MAX_AGE,"Expired authentication attempt");
                if ("cancel".equals(params.get("openid.mode"))) return callback.cancelled(getConfig());
                String steamId = SteamAssertion.validate(params,attempt.get("returnTo"),Instant.now());
                SteamAssertion.require(provider.verify(params),"Steam rejected the signature");
                String nonceKey = "ggh-steam-nonce:" + digest(params.get("openid.response_nonce"));
                SteamAssertion.require(session.singleUseObjects().putIfAbsent(nonceKey,SteamAssertion.MAX_AGE + 120),"Replayed Steam response");
                var identity = new BrokeredIdentityContext(steamId,getConfig());
                identity.setIdp(provider);
                identity.setAuthenticationSession(auth);
                identity.setBrokerUserId(getConfig().getAlias() + "." + steamId);
                identity.setUsername("steam_" + steamId);
                var json = JsonNodeFactory.instance.objectNode().put("steam_id",steamId).put("id",steamId);
                AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity,json,getConfig().getAlias());
                return callback.authenticated(identity);
            } catch (WebApplicationException e) { return e.getResponse(); }
            catch (Exception e) {
                // Never log callback URLs, signatures, cookies or state values.
                logger.warn("Steam authentication rejected (" + e.getClass().getSimpleName() + ")");
                return callback.error(getConfig(),Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
        }
    }
    boolean verify(Map<String,String> params) throws Exception { return SteamVerifier.verify(params); }
}
