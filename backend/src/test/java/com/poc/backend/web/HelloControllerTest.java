package com.poc.backend.web;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.poc.backend.config.SecurityConfig;

/**
 * Slice test for the controller plus the real SecurityConfig, running on
 * JUnit 6 (Jupiter). No live Keycloak is needed: the JwtDecoder is mocked so the
 * context loads without contacting the issuer, and spring-security-test's jwt()
 * post-processor injects a pre-authenticated token for the authorized case.
 */
@WebMvcTest(HelloController.class)
@Import(SecurityConfig.class)
class HelloControllerTest {

    @Autowired
    MockMvc mockMvc;

    // Present only so the resource-server config loads without fetching the
    // issuer's JWKS over the network during the test.
    @MockitoBean
    JwtDecoder jwtDecoder;

    @Test
    void returns401WhenNoToken() throws Exception {
        mockMvc.perform(get("/hello"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void returnsGreetingWhenAuthenticated() throws Exception {
        mockMvc.perform(get("/hello")
                .with(jwt().jwt(token -> token.claim("preferred_username", "testuser"))))
            .andExpect(status().isOk())
            .andExpect(content().string("Hello World, testuser"));
    }

    /**
     * RFC 9449 §7.1: a DPoP-bound token (carrying {@code cnf.jkt}) presented under
     * the plain {@code Bearer} scheme must be rejected, even though it is otherwise
     * a valid, authenticated token. Spring Security's own
     * {@code BearerTokenAuthenticationFilter} enforces this (via its
     * {@code isDPoPBoundAccessToken} check), so the response is the framework's
     * {@code invalid_token} bearer challenge. Asserting the challenge, not just the
     * status, keeps the test discriminating (a bare 401 would pass for many
     * unrelated reasons).
     */
    @Test
    void rejectsBoundTokenUnderBearerScheme() throws Exception {
        Jwt bound = Jwt.withTokenValue("bound-token")
            .header("alg", "ES256")
            .claim("preferred_username", "testuser")
            .claim("cnf", Map.of("jkt", "abc123"))
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .build();
        when(jwtDecoder.decode("bound-token")).thenReturn(bound);

        mockMvc.perform(get("/hello").header("Authorization", "Bearer bound-token"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string("WWW-Authenticate", containsString("Bearer")))
            .andExpect(header().string("WWW-Authenticate", containsString("invalid_token")));
    }
}
