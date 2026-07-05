package com.poc.backend.web;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.poc.backend.config.SecurityConfig;

/**
 * Slice test for {@code /server-details} plus the real SecurityConfig (same
 * pattern as {@link HelloControllerTest}): no live Keycloak, the JwtDecoder is
 * mocked, and spring-security-test's jwt() post-processor injects a
 * pre-authenticated token. Because the post-processor bypasses the real
 * converter, the {@code ACR_<acr>} authority is set explicitly to mirror what
 * SecurityConfig's converter would derive from the claim.
 */
@WebMvcTest(ServerDetailsController.class)
@Import(SecurityConfig.class)
class ServerDetailsControllerTest {

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    JwtDecoder jwtDecoder;

    @Test
    void returns401WhenNoToken() throws Exception {
        mockMvc.perform(get("/server-details"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void returns401StepUpChallengeForBasicToken() throws Exception {
        mockMvc.perform(get("/server-details")
                .with(jwt()
                    .jwt(token -> token.claim("acr", "basic"))
                    .authorities(new SimpleGrantedAuthority("ACR_basic"))))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string("WWW-Authenticate", containsString("insufficient_user_authentication")))
            .andExpect(header().string("WWW-Authenticate", containsString("acr_values=\"pro\"")));
    }

    @Test
    void returns200WithPayloadForProToken() throws Exception {
        mockMvc.perform(get("/server-details")
                .with(jwt()
                    .jwt(token -> token.claim("acr", "pro"))
                    .authorities(new SimpleGrantedAuthority("ACR_pro"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.application").exists())
            .andExpect(jsonPath("$.javaVersion").exists())
            .andExpect(jsonPath("$.startTime").exists())
            .andExpect(jsonPath("$.uptimeMillis").isNumber())
            .andExpect(jsonPath("$.activeProfiles").isArray())
            .andExpect(jsonPath("$.hostname").exists())
            .andExpect(jsonPath("$.serverTime").exists());
    }
}
