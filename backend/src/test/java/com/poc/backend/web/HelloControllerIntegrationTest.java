package com.poc.backend.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.fasterxml.jackson.databind.ObjectMapper;

import dasniko.testcontainers.keycloak.KeycloakContainer;

/**
 * Full integration test against a real Keycloak started with Testcontainers,
 * importing the same realm-export.json the production stack uses. Unlike the
 * sliced HelloControllerTest (mocked decoder), this proves the resource server
 * fetches the real JWKS and validates a real, signed token end to end.
 *
 * Requires a working Docker engine.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class HelloControllerIntegrationTest {

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
        String token = obtainAccessToken("testuser", "password");

        mockMvc.perform(get("/hello").header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(content().string("Hello World, testuser"));
    }

    /** Direct-grant token request against the live container (the realm enables it). */
    private String obtainAccessToken(String username, String password) throws Exception {
        String form = "grant_type=password"
            + "&client_id=nextjs-frontend"
            + "&client_secret=nextjs-frontend-secret-dev"
            + "&username=" + username
            + "&password=" + password;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(KEYCLOAK.getAuthServerUrl() + "/realms/web/protocol/openid-connect/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(form))
            .build();

        HttpResponse<String> response =
            HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

        return new ObjectMapper().readTree(response.body()).get("access_token").asText();
    }
}
