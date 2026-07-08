package com.poc.backend.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.poc.backend.support.KeycloakAuthCodeClient;

import dasniko.testcontainers.keycloak.KeycloakContainer;

/**
 * Full integration test against a real Keycloak started with Testcontainers,
 * importing the same realm-export.json the production stack uses. The token is
 * obtained through the real Authorization Code + PKCE flow (the same flow the
 * Next.js frontend uses), so this proves the resource server validates a real,
 * signed token end to end.
 *
 * Requires a working Docker engine.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class HelloControllerIntegrationTest {

    private static final String CLIENT_ID = "nextjs-frontend";
    private static final String CLIENT_SECRET = "nextjs-frontend-secret-dev";
    private static final String REDIRECT_URI = "http://localhost:3000/api/auth/callback/keycloak";

    @Container
    static final KeycloakContainer KEYCLOAK =
        new KeycloakContainer("quay.io/keycloak/keycloak:26.6")
            .withRealmImportFile("keycloak/realm-export.json");

    @DynamicPropertySource
    static void resourceServerProps(DynamicPropertyRegistry registry) {
        registry.add(
            "spring.security.oauth2.resourceserver.jwt.issuer-uri",
            () -> KEYCLOAK.getAuthServerUrl() + "/realms/web");
    }

    @Autowired
    MockMvc mockMvc;

    @Test
    void returns401WhenNoToken() throws Exception {
        mockMvc.perform(get("/hello"))
            .andExpect(status().isUnauthorized());
    }

    // MockMvc's default request URL (request.getRequestURL()), which the DPoP
    // proof's `htu` must match.
    private static final String HELLO_HTU = "http://localhost/hello";

    @Test
    void returnsGreetingWithRealDpopToken() throws Exception {
        KeycloakAuthCodeClient auth = auth();
        String token = auth.accessToken("testuser", "password");

        // The realm's audience mapper must put this client in `aud`, otherwise the
        // resource server's AudienceValidator would reject the token (see H-1).
        assertThat(audiencesOf(token)).contains("nextjs-frontend");

        mockMvc.perform(get("/hello")
                .header("Authorization", "DPoP " + token)
                .header("DPoP", auth.resourceProof("GET", HELLO_HTU, token)))
            .andExpect(status().isOk())
            .andExpect(content().string("Hello World, testuser"));
    }

    @Test
    void boundTokenRejectedUnderBearerScheme() throws Exception {
        // RFC 9449 §7.1: a DPoP-bound token must not be usable as a bearer token.
        // Enforced natively by Spring's BearerTokenAuthenticationFilter, which
        // answers with an invalid_token bearer challenge.
        String token = auth().accessToken("testuser", "password");

        mockMvc.perform(get("/hello").header("Authorization", "Bearer " + token))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string("WWW-Authenticate", containsString("invalid_token")));
    }

    @Test
    void dpopSchemeWithoutProofRejected() throws Exception {
        String token = auth().accessToken("testuser", "password");

        mockMvc.perform(get("/hello").header("Authorization", "DPoP " + token))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void replayedProofRejected() throws Exception {
        KeycloakAuthCodeClient auth = auth();
        String token = auth.accessToken("testuser", "password");
        String proof = auth.resourceProof("GET", HELLO_HTU, token);

        // First use of the proof is accepted; replaying the same proof (same jti)
        // is rejected by Spring's DPoP jti replay cache.
        mockMvc.perform(get("/hello").header("Authorization", "DPoP " + token).header("DPoP", proof))
            .andExpect(status().isOk());
        mockMvc.perform(get("/hello").header("Authorization", "DPoP " + token).header("DPoP", proof))
            .andExpect(status().isUnauthorized());
    }

    private static KeycloakAuthCodeClient auth() {
        return new KeycloakAuthCodeClient(
            KEYCLOAK.getAuthServerUrl(), "web", CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    }

    private static List<String> audiencesOf(String jwt) throws Exception {
        String segment = jwt.split("\\.")[1];
        segment += "=".repeat((4 - segment.length() % 4) % 4);
        JsonNode aud = new ObjectMapper()
            .readTree(Base64.getUrlDecoder().decode(segment))
            .get("aud");
        List<String> result = new ArrayList<>();
        if (aud != null && aud.isArray()) {
            aud.forEach(node -> result.add(node.asText()));
        } else if (aud != null) {
            result.add(aud.asText());
        }
        return result;
    }
}
