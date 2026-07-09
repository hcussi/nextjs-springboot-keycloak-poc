package com.poc.backend.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

/**
 * Single protected endpoint. The JWT has already been validated by the resource
 * server filter chain by the time this runs; here we just read a claim from it.
 */
@Slf4j
@RestController
public class HelloController {

    /** When true, emit non-secret request diagnostics at INFO (DEBUG env flag). */
    private final boolean debug;

    public HelloController(@Value("${DEBUG:false}") boolean debug) {
        this.debug = debug;
    }

    @GetMapping("/hello")
    public String hello(@AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        // Avoid logging the username (PII); log at debug without the value.
        log.debug("GET /hello served");
        if (debug) {
            // jkt is a public thumbprint; acr/sub are safe operational claims (no PII, no token).
            Object cnf = jwt.getClaim("cnf");
            String jkt = cnf instanceof java.util.Map<?, ?> m && m.get("jkt") instanceof String s ? s : "(none)";
            log.info("[dpop-debug] GET /hello served: acr={}, cnf.jkt={}, sub={}",
                jwt.getClaimAsString("acr"), jkt, jwt.getSubject());
        }
        return "Hello World, " + username;
    }
}
