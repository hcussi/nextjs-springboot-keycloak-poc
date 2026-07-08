package com.poc.backend.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.InputStream;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
 * Full integration test for {@code /server-details} against a real Keycloak
 * (Testcontainers, importing the production realm-export.json). Proves the
 * step-up enforcement end to end with real, signed tokens: a base (acr=basic)
 * token is refused with an RFC 9470 challenge, and a pro token obtained by
 * completing the real OTP second factor is accepted.
 *
 * Requires a working Docker engine.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class ServerDetailsControllerIntegrationTest {

    private static final String CLIENT_ID = "nextjs-frontend";
    private static final String CLIENT_SECRET = "nextjs-frontend-secret-dev";
    private static final String REDIRECT_URI = "http://localhost:3000/api/auth/callback/keycloak";
    // Dev-only seed for testuser's TOTP, matching keycloak/realm-export.json.
    private static final String TOTP_SECRET = "stepupTOTPseedDEVonly1234567890AB";

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

    // MockMvc's default request URL, which the DPoP proof's `htu` must match.
    private static final String HTU = "http://localhost/server-details";

    @Value("${app.security.stepup.acr}")
    String requiredAcr;

    private KeycloakAuthCodeClient auth() {
        return new KeycloakAuthCodeClient(
            KEYCLOAK.getAuthServerUrl(), "web", CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    }

    @Test
    void basicTokenGetsStepUpChallenge() throws Exception {
        // A valid DPoP proof but an under-assured (acr=basic) token: authentication
        // succeeds, so the RFC 9470 step-up 401 must win over any DPoP error.
        KeycloakAuthCodeClient auth = auth();
        String basic = auth.accessToken("testuser", "password"); // no acr -> acr=basic

        mockMvc.perform(get("/server-details")
                .header("Authorization", "DPoP " + basic)
                .header("DPoP", auth.resourceProof("GET", HTU, basic)))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string("WWW-Authenticate", containsString("insufficient_user_authentication")))
            .andExpect(header().string("WWW-Authenticate", containsString("acr_values=\"pro\"")));
    }

    @Test
    void proTokenReturnsServerDetails() throws Exception {
        KeycloakAuthCodeClient auth = auth();
        String pro = auth.accessToken("testuser", "password", "pro", TOTP_SECRET);

        mockMvc.perform(get("/server-details")
                .header("Authorization", "DPoP " + pro)
                .header("DPoP", auth.resourceProof("GET", HTU, pro)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.application").exists())
            .andExpect(jsonPath("$.javaVersion").exists())
            .andExpect(jsonPath("$.activeProfiles").isArray());
    }

    @Test
    void noTokenGetsOrdinary401() throws Exception {
        mockMvc.perform(get("/server-details"))
            .andExpect(status().isUnauthorized());
    }

    /**
     * The acr the backend enforces must be a level the realm actually maps, so a
     * rename in Keycloak's acr.loa.map surfaces here as a failing test rather than
     * a silent total denial of /server-details.
     */
    @Test
    void configuredAcrIsAKeyInRealmAcrLoaMap() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode realm;
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("keycloak/realm-export.json")) {
            assertThat(in).as("realm-export.json on the test classpath").isNotNull();
            realm = mapper.readTree(in);
        }
        String loaMapJson = realm.path("attributes").path("acr.loa.map").asText();
        JsonNode loaMap = mapper.readTree(loaMapJson);
        assertThat(loaMap.has(requiredAcr))
            .as("app.security.stepup.acr='%s' must be a key in realm acr.loa.map %s", requiredAcr, loaMapJson)
            .isTrue();
    }
}
