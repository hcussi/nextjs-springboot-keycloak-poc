package com.poc.backend.dpop;

/**
 * Thrown when the DPoP {@code jti} replay store cannot be reached. The proof
 * pipeline treats this as fail-closed (the request is refused), so replay
 * protection is never silently downgraded to weaker per-instance behavior
 * (PRD-4 FR-B20 / NFR-13).
 */
public class ReplayStoreUnavailableException extends RuntimeException {

    public ReplayStoreUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
