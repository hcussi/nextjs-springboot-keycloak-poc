package com.poc.backend.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class AudienceValidatorTest {

    private final AudienceValidator validator = new AudienceValidator("nextjs-frontend");

    @Test
    void acceptsTokenWithExpectedAudience() {
        Jwt jwt = jwtWithAudience(List.of("account", "nextjs-frontend"));
        assertThat(validator.validate(jwt).hasErrors()).isFalse();
    }

    @Test
    void rejectsTokenWithDifferentAudience() {
        Jwt jwt = jwtWithAudience(List.of("account"));
        assertThat(validator.validate(jwt).hasErrors()).isTrue();
    }

    @Test
    void rejectsTokenWithoutAudienceClaim() {
        Jwt jwt = Jwt.withTokenValue("token")
            .header("alg", "none")
            .subject("user")
            .issuedAt(Instant.now())
            .build();
        assertThat(validator.validate(jwt).hasErrors()).isTrue();
    }

    private static Jwt jwtWithAudience(List<String> audiences) {
        return Jwt.withTokenValue("token")
            .header("alg", "none")
            .subject("user")
            .audience(audiences)
            .issuedAt(Instant.now())
            .build();
    }
}
