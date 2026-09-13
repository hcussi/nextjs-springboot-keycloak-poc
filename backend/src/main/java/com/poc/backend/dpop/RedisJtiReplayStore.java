package com.poc.backend.dpop;

import java.time.Duration;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * Redis-backed {@link JtiReplayStore}: a single atomic {@code SET key "1" NX EX
 * <ttl>} decides first-use vs replay for every backend instance sharing the same
 * Redis. The {@code NX} makes it race-free across concurrent replays, and the
 * {@code EX} bounds the key's lifetime to the {@code iat} window so Redis stays
 * small (an expired key is a proof the freshness check would reject anyway).
 *
 * <p>Fail-closed: if Redis is unreachable, the operation raises a
 * {@link ReplayStoreUnavailableException} instead of returning a permissive
 * result, so the filter refuses the request rather than skipping replay
 * protection (PRD-4 FR-B20).
 */
@Component
public class RedisJtiReplayStore implements JtiReplayStore {

    /** Namespace so the replay keys are easy to see and scope in Redis. */
    private static final String KEY_PREFIX = "dpop:jti:";

    private final StringRedisTemplate redis;

    public RedisJtiReplayStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public boolean firstUse(String jti, Duration ttl) {
        Boolean wasSet;
        try {
            wasSet = redis.opsForValue().setIfAbsent(KEY_PREFIX + jti, "1", ttl);
        } catch (RuntimeException ex) {
            // Connection refused / timeout / pool exhaustion / any Redis-layer error:
            // fail closed with the documented signal (catch broadly, not just
            // DataAccessException, so no failure mode slips through as fail-open).
            throw new ReplayStoreUnavailableException("DPoP jti replay store unavailable", ex);
        }
        if (wasSet == null) {
            // Only happens if the command didn't actually execute (e.g. pipeline/tx
            // mode); we use neither, so treat an absent result as unavailable, not
            // as a definite first-use, to stay fail-closed.
            throw new ReplayStoreUnavailableException(
                "DPoP jti replay store returned no result", null);
        }
        // setIfAbsent returns TRUE only when the key did not exist (first use).
        return wasSet;
    }
}
