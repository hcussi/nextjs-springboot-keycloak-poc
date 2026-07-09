package com.poc.backend.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Unit test for {@link DpopBoundTokenValidator}. This is the meaningful test of
 * the "every accepted token must be DPoP-bound" control: a real unbound token is
 * impossible to mint against the DPoP-requiring Keycloak client, so the guarantee
 * is proven here at the validator level rather than via an integration test that
 * could only assert the (framework-provided) bound-token happy path.
 */
class DpopBoundTokenValidatorTest {

    private final DpopBoundTokenValidator validator = new DpopBoundTokenValidator(false);

    @Test
    void acceptsTokenWithCnfJkt() {
        OAuth2TokenValidatorResult result = validator.validate(
            jwt(token -> token.claim("cnf", Map.of("jkt", "abc123thumbprint"))));
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void rejectsTokenWithoutCnf() {
        OAuth2TokenValidatorResult result = validator.validate(jwt(token -> { }));
        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).anyMatch(e -> e.getErrorCode().equals("invalid_token"));
    }

    @Test
    void rejectsCnfWithoutJkt() {
        OAuth2TokenValidatorResult result = validator.validate(
            jwt(token -> token.claim("cnf", Map.of("x5t#S256", "some-cert-thumbprint"))));
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void rejectsBlankJkt() {
        OAuth2TokenValidatorResult result = validator.validate(
            jwt(token -> token.claim("cnf", Map.of("jkt", "   "))));
        assertThat(result.hasErrors()).isTrue();
    }

    private static Jwt jwt(Consumer<Jwt.Builder> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("t")
            .header("alg", "ES256")
            .subject("testuser")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300));
        claims.accept(builder);
        return builder.build();
    }
}
