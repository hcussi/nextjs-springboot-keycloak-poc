package com.poc.backend.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * DPoP proof-hardening configuration (iteration 4), bound from
 * {@code app.security.dpop.*} in application.yml.
 *
 * <p>All values have defaults there (backed by env vars), so nothing is
 * hardcoded: the {@code iat} acceptance window doubles as the Redis {@code jti}
 * TTL, and the nonce settings drive the server-issued {@code DPoP-Nonce} on the
 * configured {@link #nonce() paths} (only {@code /server-details} by default).
 *
 * @param iatWindowSeconds symmetric proof-age tolerance in seconds; also the
 *     Redis {@code jti} key TTL, so the two never disagree
 * @param nonce            nonce settings for the elevated endpoint(s)
 */
@ConfigurationProperties(prefix = "app.security.dpop")
public record DpopProperties(long iatWindowSeconds, Nonce nonce) {

    /**
     * Server-issued DPoP nonce settings.
     *
     * @param paths      request paths that additionally require a fresh nonce
     *     (comma-separated in config); {@code /hello} is intentionally excluded
     * @param ttlSeconds nonce validity lifetime in seconds
     * @param secret     HMAC key that signs/verifies the self-validating nonce
     *     (dev-only placeholder in this POC; never a real secret)
     */
    public record Nonce(List<String> paths, long ttlSeconds, String secret) {
    }
}
