package com.poc.backend.dpop;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import com.poc.backend.config.DpopProperties;

/**
 * Issues and verifies the server-chosen DPoP nonce for the elevated endpoint(s)
 * (PRD-4 §8.4). The nonce is <em>self-validating</em>: it carries its own expiry
 * and an HMAC over {@code random || expiry}, so <em>any</em> backend instance
 * verifies it with only the shared secret, no Redis and no per-nonce state.
 *
 * <p>Wire format (56 bytes, base64url without padding):
 * <pre>random(16) || expiryEpochSeconds(8, big-endian) || HMAC-SHA256(32)</pre>
 * The random bytes make each issued nonce unique; the expiry bounds its lifetime;
 * the HMAC makes it unforgeable. A nonce is reusable within its short lifetime,
 * which is acceptable because each proof still carries a unique {@code jti}
 * (blocked by the distributed replay store) and a fresh {@code iat} window.
 */
@Component
public class DpopNonceService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int RANDOM_LEN = 16;
    private static final int EXPIRY_LEN = Long.BYTES; // 8
    private static final int MAC_LEN = 32;            // SHA-256 output
    private static final int PAYLOAD_LEN = RANDOM_LEN + EXPIRY_LEN;
    private static final int NONCE_LEN = PAYLOAD_LEN + MAC_LEN;

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private final SecureRandom secureRandom = new SecureRandom();
    private final byte[] secret;
    private final long ttlSeconds;
    private final Clock clock;

    @Autowired
    public DpopNonceService(DpopProperties properties) {
        this(properties, Clock.systemUTC());
    }

    /** Test seam: an injectable clock makes expiry deterministic. */
    DpopNonceService(DpopProperties properties, Clock clock) {
        // Fail fast at startup rather than as a runtime 500 on the first nonce.
        Assert.hasText(properties.nonce().secret(), "app.security.dpop.nonce.secret must not be blank");
        Assert.isTrue(properties.nonce().ttlSeconds() > 0,
            "app.security.dpop.nonce.ttl-seconds must be positive");
        this.secret = properties.nonce().secret().getBytes(StandardCharsets.UTF_8);
        this.ttlSeconds = properties.nonce().ttlSeconds();
        this.clock = clock;
    }

    /** Mints a fresh nonce valid for the configured TTL. */
    public String issue() {
        byte[] random = new byte[RANDOM_LEN];
        secureRandom.nextBytes(random);
        long expiry = clock.instant().getEpochSecond() + ttlSeconds;

        byte[] payload = ByteBuffer.allocate(PAYLOAD_LEN).put(random).putLong(expiry).array();
        byte[] mac = hmac(payload);
        byte[] token = ByteBuffer.allocate(NONCE_LEN).put(payload).put(mac).array();
        return ENCODER.encodeToString(token);
    }

    /**
     * Returns {@code true} iff {@code nonce} is well-formed, its HMAC matches
     * (constant-time), and it has not expired.
     */
    public boolean validate(String nonce) {
        if (nonce == null || nonce.isBlank()) {
            return false;
        }
        byte[] token;
        try {
            token = DECODER.decode(nonce);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        if (token.length != NONCE_LEN) {
            return false;
        }

        byte[] payload = new byte[PAYLOAD_LEN];
        byte[] mac = new byte[MAC_LEN];
        System.arraycopy(token, 0, payload, 0, PAYLOAD_LEN);
        System.arraycopy(token, PAYLOAD_LEN, mac, 0, MAC_LEN);

        // Constant-time compare so a bad MAC leaks no timing signal.
        if (!MessageDigest.isEqual(hmac(payload), mac)) {
            return false;
        }
        long expiry = ByteBuffer.wrap(payload, RANDOM_LEN, EXPIRY_LEN).getLong();
        return expiry > clock.instant().getEpochSecond();
    }

    private byte[] hmac(byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (java.security.GeneralSecurityException ex) {
            // HmacSHA256 is always available and the key is non-empty; this is fatal.
            throw new IllegalStateException("Failed to compute DPoP nonce HMAC", ex);
        }
    }
}
