package de.gghub.keycloak.steam;

import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SteamAssertionTest {
    static final String RETURN = "https://login.example.test/realms/test/broker/steam/endpoint?state=test";
    static final String STEAM_ID = "76561198000000000";
    static Map<String,String> valid(Instant now) {
        var p = new HashMap<String,String>();
        p.put("state","test"); p.put("openid.ns",SteamAssertion.NS);
        p.put("openid.mode","id_res"); p.put("openid.op_endpoint",SteamAssertion.ENDPOINT);
        p.put("openid.return_to",RETURN);
        p.put("openid.identity","https://steamcommunity.com/openid/id/"+STEAM_ID);
        p.put("openid.claimed_id",p.get("openid.identity"));
        p.put("openid.response_nonce",now.toString()+"unique");
        p.put("openid.assoc_handle","handle"); p.put("openid.sig","signature");
        p.put("openid.signed","op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle");
        return p;
    }
    private final Instant now = Instant.parse("2026-11-08T12:00:00Z");
    @Test void acceptsVerifiedShape() { assertEquals(STEAM_ID,SteamAssertion.validate(valid(now),RETURN,now)); }
    @Test void rejectsChangedSecurityFields() {
        for (String key:List.of("openid.ns","openid.mode","openid.op_endpoint","openid.return_to","openid.claimed_id","openid.identity","openid.signed","openid.sig","openid.assoc_handle")) {
            var p = valid(now); p.put(key,"wrong");
            // A nonempty signature/handle is validated remotely, not by shape alone.
            if (key.equals("openid.sig") || key.equals("openid.assoc_handle")) p.put(key,"");
            assertThrows(IllegalArgumentException.class,()->SteamAssertion.validate(p,RETURN,now),key);
        }
    }
    @Test void rejectsOldFutureAndInvalidNonces() {
        for (String nonce:List.of(now.minusSeconds(301)+"old", now.plusSeconds(61)+"future", "bad", "2026-99-99T00:00:00Zinvalid")) {
            var p=valid(now);p.put("openid.response_nonce",nonce);
            assertThrows(IllegalArgumentException.class,()->SteamAssertion.validate(p,RETURN,now));
        }
    }
    @Test void rejectsNonSteamIdentifiers() {
        for (String id:List.of("http://steamcommunity.com/openid/id/"+STEAM_ID,"https://evil.test/openid/id/"+STEAM_ID,"https://steamcommunity.com/openid/id/123")) {
            var p=valid(now);p.put("openid.identity",id);p.put("openid.claimed_id",id);
            assertThrows(IllegalArgumentException.class,()->SteamAssertion.validate(p,RETURN,now));
        }
    }
    @Test void acceptsOnlyExactVerificationResponse() {
        assertTrue(SteamAssertion.verified("ns:"+SteamAssertion.NS+"\nis_valid:true\n"));
        for(String s:List.of("is_valid:true\n", "ns:"+SteamAssertion.NS+"\nis_valid:false\n", "ns:"+SteamAssertion.NS+"\nis_valid:trueevil\n", "ns:"+SteamAssertion.NS+"\nis_valid:true\nis_valid:true\n")) assertFalse(SteamAssertion.verified(s));
    }
    @Test void rejectsDuplicateAndOversizedParameters() {
        assertThrows(IllegalArgumentException.class,()->SteamAssertion.flatten(Map.of("state",List.of("a","b"))));
        assertThrows(IllegalArgumentException.class,()->SteamAssertion.flatten(Map.of("state",List.of("x".repeat(8193)))));
    }
}
