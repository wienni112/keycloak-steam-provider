package de.gghub.keycloak.steam;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;

final class SteamVerifier {
    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER).build();

    static boolean verify(Map<String,String> params) throws Exception {
        var fields = params.entrySet().stream().filter(e -> e.getKey().startsWith("openid."))
            .filter(e -> !e.getKey().equals("openid.mode"))
            .map(e -> encode(e.getKey()) + "=" + encode(e.getValue())).collect(Collectors.joining("&"));
        var request = HttpRequest.newBuilder(URI.create(SteamAssertion.ENDPOINT))
            .timeout(Duration.ofSeconds(15))
            .header("Content-Type","application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(fields + "&openid.mode=check_authentication")).build();
        var response = HTTP.send(request,HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream stream = response.body()) {
            if (response.statusCode() != 200) return false;
            byte[] body = stream.readNBytes(16385);
            return body.length <= 16384 && SteamAssertion.verified(new String(body,StandardCharsets.UTF_8));
        }
    }
    private static String encode(String value) { return URLEncoder.encode(value,StandardCharsets.UTF_8); }
}
