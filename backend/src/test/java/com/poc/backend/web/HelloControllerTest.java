package com.poc.backend.web;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
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
}
