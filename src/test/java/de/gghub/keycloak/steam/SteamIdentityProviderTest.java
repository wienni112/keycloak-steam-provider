package de.gghub.keycloak.steam;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.*;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SteamIdentityProviderTest {
    private KeycloakSession session;
    private SteamIdentityProvider provider;
    private UserAuthenticationIdentityProvider.AuthenticationCallback callback;
    private IdentityProviderModel config;
    private SingleUseObjectProvider cache;
    private Map<String,Map<String,String>> attempts;
    @BeforeEach void setup() throws Exception {
        session=mock(KeycloakSession.class,RETURNS_DEEP_STUBS);
        when(session.getContext().getRealm().getId()).thenReturn("realm-id");
        config=new IdentityProviderModel(); config.setEnabled(true);config.setAlias("steam-test"); config.setProviderId(SteamIdentityProviderFactory.ID);
        provider=spy(new SteamIdentityProvider(session,config));doReturn(true).when(provider).verify(anyMap());
        callback=mock(UserAuthenticationIdentityProvider.AuthenticationCallback.class);
        var auth = mock(AuthenticationSessionModel.class);
        when(callback.getAndVerifyAuthenticationSession("test")).thenReturn(auth);
        cache=session.singleUseObjects(); attempts=new HashMap<>();
        doAnswer(inv->{attempts.put(inv.getArgument(0),inv.getArgument(2));return null;}).when(cache).put(anyString(),anyLong(),anyMap());
        when(cache.remove(anyString())).thenAnswer(inv->attempts.remove(inv.getArgument(0)));
        when(cache.putIfAbsent(anyString(),anyLong())).thenReturn(true);
        when(callback.error(eq(config),anyString())).thenReturn(Response.status(400).build());
        when(callback.authenticated(any())).thenReturn(Response.ok().build());
    }
    private Response start() {
        var request=mock(AuthenticationRequest.class); var state=mock(IdentityBrokerState.class);
        when(request.getRedirectUri()).thenReturn("https://login.example.test/realms/test/broker/steam/endpoint");
        when(request.getState()).thenReturn(state);when(state.getEncoded()).thenReturn("test");
        return provider.performLogin(request);
    }
    private Map<String,String> params() { return SteamAssertionTest.valid(Instant.now().truncatedTo(ChronoUnit.SECONDS)); }
    @Test void derivesRealmAndReturnUrlWithoutForeignHosts() {
        var location=start().getLocation().toString();
        assertTrue(location.startsWith(SteamAssertion.ENDPOINT+"?"));
        assertTrue(location.contains("openid.realm=https%3A%2F%2Flogin.example.test%2F"));
        assertFalse(location.contains("atlasmapviewer"));
        assertEquals(1,attempts.size());
    }
    @Test void authenticatesIdAndBlocksRepeatedAttempt() throws Exception {
        start(); var endpoint=(SteamIdentityProvider.Endpoint)provider.callback(null,callback,null);
        assertEquals(200,endpoint.handle(params()).getStatus());
        verify(callback).authenticated(argThat(c->SteamAssertionTest.STEAM_ID.equals(c.getId()) && c.getAuthenticationSession()!=null));
        assertEquals(400,endpoint.handle(params()).getStatus());
        verify(provider,times(1)).verify(anyMap());
    }
    @Test void rejectsFailedRemoteVerificationAndNonceReplay() throws Exception {
        start();doReturn(false).when(provider).verify(anyMap());
        var endpoint=(SteamIdentityProvider.Endpoint)provider.callback(null,callback,null);
        assertEquals(400,endpoint.handle(params()).getStatus());verify(callback,never()).authenticated(any());
        start();doReturn(true).when(provider).verify(anyMap());when(cache.putIfAbsent(anyString(),anyLong())).thenReturn(false);
        assertEquals(400,endpoint.handle(params()).getStatus());verify(callback,never()).authenticated(any());
    }
    @Test void rejectsBadReturnBeforeRemoteCall() throws Exception {
        start();var p=params();p.put("openid.return_to","https://evil.test/");
        var endpoint=(SteamIdentityProvider.Endpoint)provider.callback(null,callback,null);
        assertEquals(400,endpoint.handle(p).getStatus());verify(provider,never()).verify(anyMap());
    }
    @Test void cancellationRequiresAValidAttempt() {
        start();when(callback.cancelled(config)).thenReturn(Response.status(302).build());
        var endpoint=(SteamIdentityProvider.Endpoint)provider.callback(null,callback,null);
        assertEquals(302,endpoint.handle(Map.of("state","test","openid.mode","cancel")).getStatus());
        assertEquals(400,endpoint.handle(Map.of("state","test","openid.mode","cancel")).getStatus());
    }
}
