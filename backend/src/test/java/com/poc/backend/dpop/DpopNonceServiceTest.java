package com.poc.backend.dpop;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.poc.backend.config.DpopProperties;

/**
 * Unit tests for the HMAC self-validating DPoP nonce: a freshly issued nonce
 * validates, an expired one does not, and any tampering (payload or MAC) or a
 * wrong key is rejected.
 */
class DpopNonceServiceTest {

    private static final String SECRET = "unit-test-dpop-nonce-secret";

    private static DpopProperties props(long ttlSeconds, String secret) {
        return new DpopProperties(60, new DpopProperties.Nonce(List.of("/server-details"), ttlSeconds, secret));
    }

    private static DpopNonceService service(long ttlSeconds, String secret) {
        return new DpopNonceService(props(ttlSeconds, secret));
    }

    @Test
    void freshNonceValidates() {
        DpopNonceService service = service(60, SECRET);
        assertThat(service.validate(service.issue())).isTrue();
    }

    @Test
    void expiredNonceIsRejected() {
        // Issue at T with a 60s TTL, then validate at T + 61s (same secret): expired.
        Instant t = Instant.parse("2026-08-03T00:00:00Z");
        DpopNonceService issuer = new DpopNonceService(props(60, SECRET), Clock.fixed(t, ZoneOffset.UTC));
        DpopNonceService later = new DpopNonceService(
            props(60, SECRET), Clock.fixed(t.plus(Duration.ofSeconds(61)), ZoneOffset.UTC));
        assertThat(later.validate(issuer.issue())).isFalse();
    }

    @Test
    void nonceFromAnotherKeyIsRejected() {
        DpopNonceService issuer = service(60, SECRET);
        DpopNonceService verifier = service(60, "a-different-secret");
        assertThat(verifier.validate(issuer.issue())).isFalse();
    }

    @Test
    void tamperedNonceIsRejected() {
        DpopNonceService service = service(60, SECRET);
        String nonce = service.issue();
        // Flip a character to corrupt the encoded token (payload or MAC).
        char c = nonce.charAt(0);
        String tampered = (c == 'A' ? 'B' : 'A') + nonce.substring(1);
        assertThat(service.validate(tampered)).isFalse();
    }

    @Test
    void malformedNonceIsRejected() {
        DpopNonceService service = service(60, SECRET);
        assertThat(service.validate(null)).isFalse();
        assertThat(service.validate("")).isFalse();
        assertThat(service.validate("not-base64url!!")).isFalse();
        assertThat(service.validate("c2hvcnQ")).isFalse(); // valid base64url but wrong length
    }

    @Test
    void eachIssuedNonceIsUnique() {
        DpopNonceService service = service(60, SECRET);
        assertThat(service.issue()).isNotEqualTo(service.issue());
    }
}
