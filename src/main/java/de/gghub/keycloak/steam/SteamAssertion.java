package de.gghub.keycloak.steam;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.regex.Pattern;

/** Pure validation before a fixed-endpoint, server-to-server signature check. */
final class SteamAssertion {
    static final String ENDPOINT = "https://steamcommunity.com/openid/login";
    static final String NS = "http://specs.openid.net/auth/2.0";
    static final long MAX_AGE = 300;
    private static final Pattern ID = Pattern.compile("https://steamcommunity\\.com/openid/id/([0-9]{17})");
    private SteamAssertion() {}

    static String validate(Map<String,String> p, String expectedReturn, Instant now) {
        require(NS.equals(p.get("openid.ns")), "Invalid OpenID namespace");
        require("id_res".equals(p.get("openid.mode")), "Invalid OpenID response mode");
        require(ENDPOINT.equals(p.get("openid.op_endpoint")), "Invalid Steam endpoint");
        require(expectedReturn.equals(p.get("openid.return_to")), "Return URL mismatch");
        require(Objects.equals(p.get("openid.claimed_id"), p.get("openid.identity")), "Identity mismatch");
        var match = ID.matcher(p.getOrDefault("openid.claimed_id", ""));
        require(match.matches(), "Invalid Steam ID");
        require(!p.getOrDefault("openid.sig", "").isBlank(), "Missing signature");
        require(!p.getOrDefault("openid.assoc_handle", "").isBlank(), "Missing association handle");
        var signed = new HashSet<>(Arrays.asList(p.getOrDefault("openid.signed", "").split(",")));
        require(signed.containsAll(List.of("op_endpoint","claimed_id","identity","return_to","response_nonce","assoc_handle")), "Required fields are unsigned");
        String nonce = p.getOrDefault("openid.response_nonce", "");
        require(nonce.length() > 20 && nonce.length() <= 255, "Invalid nonce");
        try {
            Instant timestamp = Instant.parse(nonce.substring(0,20));
            require(!timestamp.isBefore(now.minusSeconds(MAX_AGE)) && !timestamp.isAfter(now.plusSeconds(60)), "Expired or future nonce");
        } catch (DateTimeParseException e) { throw new IllegalArgumentException("Invalid nonce timestamp"); }
        return match.group(1);
    }

    static Map<String,String> flatten(Map<String,List<String>> input) {
        require(input.size() <= 32, "Too many response parameters");
        var out = new HashMap<String,String>();
        input.forEach((key, values) -> {
            require(key != null && key.length() <= 128 && values != null && values.size() == 1,
                "Duplicate or invalid response parameter");
            String value = values.get(0);
            require(value != null && value.length() <= 8192, "Oversized response parameter");
            out.put(key,value);
        });
        return out;
    }

    static boolean verified(String body) {
        if (body == null || body.length() > 16384) return false;
        var pairs = new HashMap<String,String>();
        for (String line : body.split("\\n")) {
            if (line.isEmpty()) continue;
            int colon = line.indexOf(':');
            if (colon <= 0 || pairs.putIfAbsent(line.substring(0,colon),line.substring(colon+1)) != null) return false;
        }
        return NS.equals(pairs.get("ns")) && "true".equals(pairs.get("is_valid"));
    }

    static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}
