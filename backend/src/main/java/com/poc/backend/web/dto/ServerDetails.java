package com.poc.backend.web.dto;

import java.time.Instant;
import java.util.List;

/**
 * Non-sensitive runtime facts about the backend, returned by the elevated
 * (acr=pro) {@code GET /server-details} endpoint. Deliberately carries no
 * secrets, tokens, credentials, or raw environment dumps (PRD-2 §3.4).
 */
public record ServerDetails(
    String application,
    String version,
    String javaVersion,
    Instant startTime,
    long uptimeMillis,
    List<String> activeProfiles,
    String hostname,
    Instant serverTime) {
}
