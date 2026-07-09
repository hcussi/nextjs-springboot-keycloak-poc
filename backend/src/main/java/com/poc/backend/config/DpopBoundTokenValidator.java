package com.poc.backend.config;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Requires every accepted access token to be DPoP sender-constrained, i.e. to
 * carry a {@code cnf.jkt} confirmation claim (RFC 9449 §6). This is enforced
 * independently of the authorization scheme, so it holds on both the {@code DPoP}
 * and {@code Bearer} paths.
 *
 * <p>Why the resource server checks this itself rather than trusting Keycloak's
 * per-client "Require DPoP bound tokens" toggle: without an independent check, a
 * token minted for this audience that happens to lack {@code cnf} (a
 * misconfigured client sharing the audience, or the Keycloak toggle being turned
 * off) would be accepted as a plain bearer token with full access, silently
 * reopening the very downgrade DPoP exists to prevent. With this validator such a
 * token is rejected outright, so the sender-constraint does not rest on the IdP
 * configuration alone.
 *
 * <p>Note the framework's {@code BearerTokenAuthenticationFilter} already refuses
 * a {@code cnf}-bound token presented under the {@code Bearer} scheme; this
 * validator is the complementary half, refusing an <em>un</em>bound token under
 * any scheme.
 */
public final class DpopBoundTokenValidator implements OAuth2TokenValidator<Jwt> {

    private static final Logger log = LoggerFactory.getLogger(DpopBoundTokenValidator.class);

    private static final OAuth2Error MISSING_CNF = new OAuth2Error(
        "invalid_token",
        "The access token must be DPoP-bound (missing cnf.jkt confirmation claim)",
        "https://datatracker.ietf.org/doc/html/rfc9449");

    /** When true, emit non-secret DPoP diagnostics at INFO (DEBUG env flag). */
    private final boolean debug;

    public DpopBoundTokenValidator(boolean debug) {
        this.debug = debug;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        Object cnf = token.getClaim("cnf");
        if (cnf instanceof Map<?, ?> confirmation
                && confirmation.get("jkt") instanceof String thumbprint
                && !thumbprint.isBlank()) {
            if (debug) {
                // jkt is a public thumbprint (not a secret); acr/aud/sub are safe operational claims.
                log.info("[dpop-debug] token accepted: cnf.jkt={}, acr={}, aud={}, sub={}",
                    thumbprint, token.getClaimAsString("acr"), token.getAudience(), token.getSubject());
            }
            return OAuth2TokenValidatorResult.success();
        }
        if (debug) {
            log.info("[dpop-debug] token REJECTED: missing cnf.jkt (not DPoP-bound), aud={}, sub={}",
                token.getAudience(), token.getSubject());
        }
        return OAuth2TokenValidatorResult.failure(MISSING_CNF);
    }
}
