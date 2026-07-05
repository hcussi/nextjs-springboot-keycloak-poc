package com.poc.backend.support;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.joining;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test helper that runs the OAuth2 Authorization Code flow (with PKCE) against a
 * live Keycloak and returns an access token, driven over HTTP since there is no
 * browser in a test: request the authorize endpoint, submit the login form
 * (reusing the session cookies), capture the redirect `code`, and exchange it
 * (plus the PKCE verifier and the confidential client secret) for tokens.
 *
 * Cookies are tracked manually rather than via java.net.CookieManager, which
 * does not reliably resend Keycloak's session cookies for a `localhost` host.
 *
 * Reusable across integration tests; construct once per Keycloak/realm/client.
 */
public class KeycloakAuthCodeClient {

    private static final Pattern LOGIN_ACTION =
        Pattern.compile("action=\"([^\"]*login-actions/authenticate[^\"]*)\"");

    private final String realmUrl;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * @param authServerUrl Keycloak base URL (e.g. {@code container.getAuthServerUrl()})
     * @param realm         realm name
     * @param clientId      confidential client id
     * @param clientSecret  client secret
     * @param redirectUri   a redirect URI registered on the client
     */
    public KeycloakAuthCodeClient(String authServerUrl, String realm, String clientId,
                                  String clientSecret, String redirectUri) {
        this.realmUrl = authServerUrl + "/realms/" + realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
    }

    /** Logs the user in via the Authorization Code + PKCE flow and returns the access token (base level). */
    public String accessToken(String username, String password) throws Exception {
        return accessToken(username, password, null, null);
    }

    /**
     * Logs the user in via Authorization Code + PKCE, optionally requesting a
     * step-up assurance level and completing the TOTP second factor.
     *
     * @param acrValues  requested {@code acr_values} (e.g. {@code "pro"}), or null for a base login
     * @param totpSecret raw TOTP seed to complete the OTP form when step-up prompts it, or null
     */
    public String accessToken(String username, String password, String acrValues, String totpSecret) throws Exception {
        HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
        Map<String, String> cookies = new LinkedHashMap<>();

        String codeVerifier = randomUrlToken(32);
        String codeChallenge = base64Url(
            MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(UTF_8)));
        String state = randomUrlToken(16);

        // 1) Authorize request -> login page HTML containing the form action.
        String authorizeUrl = realmUrl + "/protocol/openid-connect/auth"
            + "?response_type=code"
            + "&client_id=" + clientId
            + "&redirect_uri=" + enc(redirectUri)
            + "&scope=" + enc("openid profile email")
            + "&state=" + state
            + "&code_challenge=" + codeChallenge
            + "&code_challenge_method=S256"
            + (acrValues != null ? "&acr_values=" + enc(acrValues) : "");
        HttpResponse<String> loginPage = send(client, cookies,
            HttpRequest.newBuilder(URI.create(authorizeUrl)).GET());
        String formAction = extractLoginAction(loginPage);

        // 2) Submit credentials. A base login redirects straight to the callback;
        //    a step-up login instead returns the OTP form (HTTP 200).
        String formBody = "username=" + enc(username)
            + "&password=" + enc(password)
            + "&credentialId=";
        HttpResponse<String> afterLogin = send(client, cookies,
            HttpRequest.newBuilder(URI.create(formAction))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody)));

        String location = afterLogin.headers().firstValue("Location").orElse(null);
        if (location == null) {
            // 2b) Step-up: complete the OTP form with a computed TOTP.
            if (totpSecret == null) {
                throw new IllegalStateException("Password step returned no redirect (OTP expected?) "
                    + "but no TOTP secret was provided: HTTP " + afterLogin.statusCode() + ": " + snippet(afterLogin.body()));
            }
            String otpAction = extractLoginAction(afterLogin);
            String otpBody = "otp=" + enc(totp(totpSecret)) + "&login=" + enc("Sign In");
            HttpResponse<String> afterOtp = send(client, cookies,
                HttpRequest.newBuilder(URI.create(otpAction))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(otpBody)));
            location = afterOtp.headers().firstValue("Location").orElseThrow(() ->
                new IllegalStateException("Expected a callback redirect after OTP but got HTTP "
                    + afterOtp.statusCode() + ": " + snippet(afterOtp.body())));
        }
        String code = queryParam(location, "code");

        // 3) Exchange the code (+ PKCE verifier + client secret) for tokens.
        String tokenForm = "grant_type=authorization_code"
            + "&code=" + enc(code)
            + "&redirect_uri=" + enc(redirectUri)
            + "&client_id=" + clientId
            + "&client_secret=" + clientSecret
            + "&code_verifier=" + codeVerifier;
        HttpResponse<String> tokenResponse = send(client, cookies,
            HttpRequest.newBuilder(URI.create(realmUrl + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(tokenForm)));
        var json = mapper.readTree(tokenResponse.body());
        if (!json.has("access_token")) {
            throw new IllegalStateException("No access_token in token response: " + snippet(tokenResponse.body()));
        }
        return json.get("access_token").asText();
    }

    /** Sends the request with the accumulated cookies, then records any Set-Cookie values. */
    private static HttpResponse<String> send(HttpClient client, Map<String, String> cookies,
                                             HttpRequest.Builder builder) throws Exception {
        if (!cookies.isEmpty()) {
            builder.header("Cookie", cookies.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(joining("; ")));
        }
        HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        for (String setCookie : response.headers().allValues("set-cookie")) {
            String nameValue = setCookie.split(";", 2)[0];
            int eq = nameValue.indexOf('=');
            if (eq > 0) {
                String value = nameValue.substring(eq + 1).trim();
                if (!value.isEmpty()) {
                    cookies.put(nameValue.substring(0, eq).trim(), value);
                }
            }
        }
        return response;
    }

    private static String extractLoginAction(HttpResponse<String> response) {
        Matcher matcher = LOGIN_ACTION.matcher(response.body());
        if (!matcher.find()) {
            throw new IllegalStateException("Login form action not found (HTTP "
                + response.statusCode() + "): " + snippet(response.body()));
        }
        return matcher.group(1).replace("&amp;", "&");
    }

    private static String queryParam(String url, String name) {
        String query = URI.create(url).getQuery();
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equals(name)) {
                return URLDecoder.decode(pair.substring(eq + 1), UTF_8);
            }
        }
        throw new IllegalStateException("Query parameter '" + name + "' not found in " + url);
    }

    /**
     * RFC 6238 TOTP for the current 30s window: HmacSHA1, 6 digits, secret used
     * as raw UTF-8 bytes (matching the realm OTP policy and how Keycloak stores
     * the seed). Same computation as {@code scripts/totp.mjs}.
     */
    private static String totp(String secret) throws Exception {
        long counter = System.currentTimeMillis() / 1000L / 30L;
        byte[] message = ByteBuffer.allocate(8).putLong(counter).array();
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(secret.getBytes(UTF_8), "HmacSHA1"));
        byte[] hash = mac.doFinal(message);
        int offset = hash[hash.length - 1] & 0x0f;
        int binary = ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | (hash[offset + 3] & 0xff);
        return String.format("%06d", binary % 1_000_000);
    }

    private static String randomUrlToken(int bytes) {
        byte[] buffer = new byte[bytes];
        new SecureRandom().nextBytes(buffer);
        return base64Url(buffer);
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, UTF_8);
    }

    private static String snippet(String body) {
        if (body == null) {
            return "<no body>";
        }
        String trimmed = body.strip();
        return trimmed.length() > 300 ? trimmed.substring(0, 300) + "..." : trimmed;
    }
}
