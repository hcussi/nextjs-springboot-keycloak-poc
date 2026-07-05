package com.poc.backend.config;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Emits an RFC 9470 step-up challenge. When an already-authenticated request is
 * denied for lacking the required assurance level (the {@code acr} authority),
 * this responds {@code 401} with
 * <pre>WWW-Authenticate: Bearer error="insufficient_user_authentication",
 *   error_description="...", acr_values="&lt;required&gt;"</pre>
 * instead of the default opaque {@code 403}, so the client knows to
 * re-authenticate at a higher level and which level to request.
 *
 * <p>A missing or invalid token never reaches here: that is an
 * <em>authentication</em> failure handled by the resource server's ordinary
 * {@code 401} entry point. This handler only fires for authenticated principals.
 * It emits the step-up challenge only when the principal actually lacks the
 * required authority; any other denial (should a non-{@code acr} rule ever be
 * added) falls through to a plain {@code 403} rather than being mislabeled.
 */
public class StepUpAccessDeniedHandler implements AccessDeniedHandler {

    private final String requiredAcr;
    private final String requiredAuthority;

    public StepUpAccessDeniedHandler(String requiredAcr, String requiredAuthority) {
        this.requiredAcr = requiredAcr;
        this.requiredAuthority = requiredAuthority;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        if (lacksRequiredLevel()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader("WWW-Authenticate",
                "Bearer error=\"insufficient_user_authentication\", "
                + "error_description=\"A higher authentication level is required\", "
                + "acr_values=\"" + requiredAcr + "\"");
        } else {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    private boolean lacksRequiredLevel() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return true;
        }
        return authentication.getAuthorities().stream()
            .noneMatch(authority -> requiredAuthority.equals(authority.getAuthority()));
    }
}
