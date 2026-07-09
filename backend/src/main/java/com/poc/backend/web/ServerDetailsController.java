package com.poc.backend.web;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.poc.backend.web.dto.ServerDetails;

import lombok.extern.slf4j.Slf4j;

/**
 * Elevated (acr=pro) endpoint returning non-sensitive runtime facts about the
 * backend. Access is gated by the step-up authority in SecurityConfig: a base
 * (acr=basic) token is refused with an RFC 9470 step-up challenge before this
 * method runs, so by the time we get here the caller has proven LoA 2.
 *
 * Exposes only innocuous operational data (never secrets, tokens, or full env
 * dumps), read from {@link Environment}, {@link RuntimeMXBean}, and optionally
 * {@link BuildProperties} when a build-info file is present.
 */
@Slf4j
@RestController
public class ServerDetailsController {

    private final Environment environment;
    private final ObjectProvider<BuildProperties> buildProperties;
    private final RuntimeMXBean runtime = ManagementFactory.getRuntimeMXBean();
    /** When true, emit non-secret request diagnostics at INFO (DEBUG env flag). */
    private final boolean debug;

    public ServerDetailsController(Environment environment, ObjectProvider<BuildProperties> buildProperties,
            @org.springframework.beans.factory.annotation.Value("${DEBUG:false}") boolean debug) {
        this.environment = environment;
        this.buildProperties = buildProperties;
        this.debug = debug;
    }

    @GetMapping("/server-details")
    public ServerDetails serverDetails() {
        BuildProperties build = buildProperties.getIfAvailable();
        log.debug("GET /server-details served");
        if (debug) {
            // Reached only after the acr=pro step-up gate passed; safe to note.
            log.info("[stepup-debug] GET /server-details served (elevated acr passed the step-up gate)");
        }
        return new ServerDetails(
            environment.getProperty("spring.application.name", "backend"),
            build != null ? build.getVersion() : "dev",
            System.getProperty("java.version"),
            Instant.ofEpochMilli(runtime.getStartTime()),
            runtime.getUptime(),
            List.of(environment.getActiveProfiles()),
            hostname(),
            Instant.now());
    }

    private static String hostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            return "unknown";
        }
    }
}
