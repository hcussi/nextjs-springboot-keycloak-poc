package com.poc.backend.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

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
        new KeycloakContainer("quay.io/keycloak/keycloak:26.3")
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

    @Test
    void returnsGreetingWithRealToken() throws Exception {
        KeycloakAuthCodeClient auth = new KeycloakAuthCodeClient(
            KEYCLOAK.getAuthServerUrl(), "web", CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
        String token = auth.accessToken("testuser", "password");

        mockMvc.perform(get("/hello").header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(content().string("Hello World, testuser"));
    }
}
