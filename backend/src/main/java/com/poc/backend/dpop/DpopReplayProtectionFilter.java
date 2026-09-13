package com.poc.backend.dpop;

import java.io.IOException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.poc.backend.config.DpopProperties;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Hardens the DPoP proof pipeline beyond the framework defaults (iteration 4).
 * It runs <em>after</em> Spring Security has already authenticated the request
 * (signature, {@code typ}/{@code htm}/{@code htu}/{@code ath}/{@code cnf} all
 * verified) and <em>before</em> the authorization check, and enforces three
 * things on the already-trusted proof:
 *
 * <ol>
 *   <li><b>Configurable symmetric {@code iat} window</b> ({@link
 *       DpopProperties#iatWindowSeconds()}): a proof older or further in the
 *       future than the window is rejected (the framework's built-in check only
 *       bounds future-dating).</li>
 *   <li><b>Distributed {@code jti} replay</b> via {@link JtiReplayStore} (Redis):
 *       a proof {@code jti} is single-use across <em>all</em> instances, not just
 *       within one JVM. If the store is unreachable the request fails closed
 *       ({@code 503}).</li>
 *   <li><b>Server-issued nonce</b> on the configured paths (default {@code
 *       /server-details}): a proof without a valid, unexpired {@code nonce} is
 *       answered with a fresh {@code DPoP-Nonce} and {@code use_dpop_nonce}. This
 *       runs before authorization, so the nonce challenge precedes the RFC 9470
 *       {@code acr} step-up challenge.</li>
 * </ol>
 *
 * <p>Only requests that DPoP-<em>authenticated</em> (a real, non-anonymous principal
 * under the {@code DPoP} authorization scheme) and carried a {@code DPoP} proof are
 * inspected; anything else passes straight through and is handled downstream as
 * before. Under exactly those conditions the framework has already verified that
 * exact proof (the proof header is single-valued, enforced upstream), so its claims
 * are read here without re-verifying the signature.
 */
public class DpopReplayProtectionFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DpopReplayProtectionFilter.class);

    private static final String DPOP_HEADER = "DPoP";
    private static final String NONCE_HEADER = "DPoP-Nonce";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    /** The DPoP authorization scheme, with its trailing space (RFC 9449). */
    private static final String DPOP_SCHEME_PREFIX = "DPoP ";

    private final JtiReplayStore replayStore;
    private final DpopNonceService nonceService;
    private final long iatWindowSeconds;
    /** Matchers for the nonce-required paths, built the same way authorization matches paths. */
    private final List<RequestMatcher> nonceMatchers;
    /** When true, emit non-secret DPoP diagnostics at INFO (DEBUG env flag). */
    private final boolean debug;

    public DpopReplayProtectionFilter(JtiReplayStore replayStore, DpopNonceService nonceService,
            DpopProperties properties, PathPatternRequestMatcher.Builder pathMatcherBuilder, boolean debug) {
        Assert.isTrue(properties.iatWindowSeconds() > 0,
            "app.security.dpop.iat-window-seconds must be positive");
        this.replayStore = replayStore;
        this.nonceService = nonceService;
        this.iatWindowSeconds = properties.iatWindowSeconds();
        // Build the nonce path matchers from a builder that carries the SAME
        // PathPatternParser Spring Security's requestMatchers(...) uses for
        // authorization (see SecurityConfig#dpopNoncePathMatcherBuilder). This keeps
        // the nonce requirement and the /server-details authorization rule matching
        // identical paths: the requirement can't be dodged by an encoded path that
        // getRequestURI() would leave unnormalized, and it can't silently diverge if
        // the app ever customizes MVC path matching, since both share one parser.
        List<String> paths = properties.nonce().paths();
        this.nonceMatchers = (paths == null ? List.<String>of() : paths).stream()
            .map(String::strip)
            .filter(StringUtils::hasText)
            .<RequestMatcher>map(pathMatcherBuilder::matcher)
            .toList();
        this.debug = debug;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        String proofHeader = request.getHeader(DPOP_HEADER);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // Require a genuinely authenticated principal (not the anonymous token, whose
        // isAuthenticated() is also true) AND that the request actually used the DPoP
        // authorization scheme. This is what makes it safe to read the proof's claims
        // without re-verifying its signature: only then has the framework already
        // verified THIS DPoP proof (the proof header is single-valued, enforced
        // upstream), so the claims we read are the ones it validated. A request that
        // merely carries a raw DPoP header without DPoP-authenticating (anonymous, or
        // Bearer) is left to the ordinary chain, so unverified input never reaches the
        // replay store or issues a nonce.
        boolean authenticated = authentication != null
            && authentication.isAuthenticated()
            && !(authentication instanceof AnonymousAuthenticationToken);
        boolean dpopScheme = StringUtils.startsWithIgnoreCase(
            request.getHeader(AUTHORIZATION_HEADER), DPOP_SCHEME_PREFIX);

        // Only DPoP-authenticated requests are hardened here; everything else
        // (no proof, unauthenticated, or a non-DPoP scheme) passes straight through.
        if (proofHeader == null || proofHeader.isBlank() || !authenticated || !dpopScheme) {
            chain.doFilter(request, response);
            return;
        }

        JWTClaimsSet claims;
        try {
            claims = SignedJWT.parse(proofHeader).getJWTClaimsSet();
        } catch (ParseException ex) {
            // The framework already parsed this proof to authenticate the request,
            // so this is unexpected; refuse rather than pass an unreadable proof.
            invalidProof(request, response, "Malformed DPoP proof");
            return;
        }

        String jti = claims.getJWTID();
        Date issuedAt = claims.getIssueTime();
        if (jti == null || jti.isBlank() || issuedAt == null) {
            invalidProof(request, response, "DPoP proof missing jti or iat");
            return;
        }

        long ageSeconds = Math.abs(Instant.now().getEpochSecond() - issuedAt.toInstant().getEpochSecond());
        if (ageSeconds > iatWindowSeconds) {
            invalidProof(request, response, "DPoP proof iat outside the " + iatWindowSeconds + "s window");
            return;
        }

        try {
            if (!replayStore.firstUse(jti, Duration.ofSeconds(iatWindowSeconds))) {
                invalidProof(request, response, "DPoP proof replayed (jti already used)");
                return;
            }
        } catch (ReplayStoreUnavailableException ex) {
            // Fail closed: never serve a DPoP request without a working replay check.
            storeUnavailable(request, response, ex);
            return;
        }

        if (requiresNonce(request)) {
            String nonce = readNonceClaim(claims);
            if (!nonceService.validate(nonce)) {
                nonceChallenge(request, response);
                return;
            }
        }

        chain.doFilter(request, response);
    }

    /** True when the request path is one of the configured nonce-required paths. */
    private boolean requiresNonce(HttpServletRequest request) {
        return nonceMatchers.stream().anyMatch(matcher -> matcher.matches(request));
    }

    private String readNonceClaim(JWTClaimsSet claims) {
        try {
            return claims.getStringClaim("nonce");
        } catch (ParseException ex) {
            return null; // non-string nonce -> treat as absent/invalid
        }
    }

    private void invalidProof(HttpServletRequest request, HttpServletResponse response,
            String description) throws IOException {
        if (debug) {
            log.info("[dpop-debug] {} refused: {}", request.getRequestURI(), description);
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader(WWW_AUTHENTICATE,
            "DPoP error=\"invalid_dpop_proof\", error_description=\"" + description + "\"");
        writeJson(response, "invalid_dpop_proof", description);
    }

    private void nonceChallenge(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String nonce = nonceService.issue();
        if (debug) {
            log.info("[dpop-debug] {} requires a fresh DPoP nonce; issuing use_dpop_nonce challenge",
                request.getRequestURI());
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader(NONCE_HEADER, nonce);
        response.setHeader(WWW_AUTHENTICATE,
            "DPoP error=\"use_dpop_nonce\", "
            + "error_description=\"Resource server requires a fresh DPoP nonce\"");
        writeJson(response, "use_dpop_nonce", "Resource server requires a fresh DPoP nonce");
    }

    private void storeUnavailable(HttpServletRequest request, HttpServletResponse response,
            ReplayStoreUnavailableException ex) throws IOException {
        // Non-secret: log the cause so an operator can see Redis is down.
        log.warn("[dpop] refusing {} fail-closed: replay store unavailable ({})",
            request.getRequestURI(), ex.getCause() != null ? ex.getCause().getMessage() : ex.getMessage());
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        writeJson(response, "replay_store_unavailable",
            "DPoP replay protection is temporarily unavailable");
    }

    private void writeJson(HttpServletResponse response, String error, String description)
            throws IOException {
        response.setContentType("application/json");
        response.getWriter().write(
            "{\"error\":\"" + error + "\",\"error_description\":\"" + description + "\"}");
    }
}
