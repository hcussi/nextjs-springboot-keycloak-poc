package com.poc.backend.dpop;

import java.time.Duration;

/**
 * Records DPoP proof {@code jti} values so each proof is single-use. Backed by
 * Redis in the running app ({@link RedisJtiReplayStore}) so the decision is
 * shared across all backend instances (RFC 9449 replay protection, made
 * distributed); a test can supply an in-memory implementation.
 */
public interface JtiReplayStore {

    /**
     * Atomically remembers {@code jti} for {@code ttl} and reports whether this
     * is its first use.
     *
     * @param jti the proof's {@code jti} claim
     * @param ttl how long to remember it (the DPoP {@code iat} window, after
     *     which a replay is rejected by the freshness check anyway)
     * @return {@code true} if {@code jti} was not seen before (accept the proof);
     *     {@code false} if it was already recorded (a replay)
     * @throws ReplayStoreUnavailableException if the store cannot be reached, so
     *     the caller can fail closed rather than silently skip the check
     */
    boolean firstUse(String jti, Duration ttl);
}
