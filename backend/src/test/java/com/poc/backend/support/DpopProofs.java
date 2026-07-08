package com.poc.backend.support;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Test-only DPoP (RFC 9449) proof factory used by the integration tests to talk
 * to the DPoP-requiring Keycloak client and the DPoP-enforcing resource server.
 *
 * <p>A DPoP proof is an ES256-signed JWT with header {@code {typ:"dpop+jwt", jwk:
 * <public key>}} and claims {@code jti/htm/htu/iat} plus, on resource requests,
 * {@code ath} (the base64url SHA-256 of the access token). Keycloak binds the
 * issued token to the proof key's SHA-256 thumbprint ({@code cnf.jkt}); the same
 * key must therefore sign every later resource proof, so a caller holds one
 * {@link ECKey} across a token and its resource calls.
 */
public final class DpopProofs {

    private DpopProofs() {
    }

    /** A fresh ES256 (P-256) key pair for one DPoP session. */
    public static ECKey generateKey() throws Exception {
        return new ECKeyGenerator(Curve.P_256)
            .keyID(UUID.randomUUID().toString())
            .generate();
    }

    /** Proof for a token-endpoint request (no {@code ath}). */
    public static String tokenProof(ECKey key, String htu, String nonce) throws Exception {
        return proof(key, "POST", htu, null, nonce);
    }

    /** Proof for a resource request, binding it to {@code accessToken} via {@code ath}. */
    public static String resourceProof(ECKey key, String htm, String htu, String accessToken) throws Exception {
        return proof(key, htm, htu, accessToken, null);
    }

    /**
     * Signs a DPoP proof. {@code accessToken} adds the {@code ath} claim; {@code
     * nonce} is echoed when a server answered with {@code use_dpop_nonce}.
     */
    public static String proof(ECKey key, String htm, String htu, String accessToken, String nonce)
            throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(key.toPublicJWK())
            .build();

        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
            .jwtID(UUID.randomUUID().toString())
            .claim("htm", htm)
            .claim("htu", htu.split("[?#]", 2)[0]) // strip query/fragment per RFC 9449
            .issueTime(Date.from(Instant.now()));
        if (accessToken != null) {
            claims.claim("ath", Base64URL.encode(sha256(accessToken)).toString());
        }
        if (nonce != null) {
            claims.claim("nonce", nonce);
        }

        SignedJWT jwt = new SignedJWT(header, claims.build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static byte[] sha256(String value) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-256")
            .digest(value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }
}
