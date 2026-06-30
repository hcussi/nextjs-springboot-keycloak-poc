package com.poc.backend.web;

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

    @GetMapping("/hello")
    public String hello(@AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        log.info("GET /hello served for user '{}'", username);
        return "Hello World, " + username;
    }
}
