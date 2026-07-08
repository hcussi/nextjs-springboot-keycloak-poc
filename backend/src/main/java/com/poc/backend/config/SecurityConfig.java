package com.poc.backend.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Configures the app as an OAuth2 resource server: every request requires a
 * valid JWT (validated against Keycloak via the issuer-uri in application.yml).
 *
 * <p>Step-up (iteration 2): the token's {@code acr} claim is mapped to an
 * {@code ACR_<value>} authority, and {@code /server-details} requires the
 * elevated level (default {@code acr=pro}). A valid but under-assured token is
 * refused with an RFC 9470 challenge (see {@link StepUpAccessDeniedHandler}),
 * not a bare 403. {@code /hello} keeps requiring only authentication.
 *
 * <p>DPoP (iteration 3): Keycloak issues sender-constrained (DPoP-bound) access
 * tokens. Spring Security <em>auto-enables</em> DPoP proof validation for the
 * {@code DPoP} authorization scheme whenever {@code DPoPProofJwtDecoderFactory}
 * is on the classpath: the proof is checked (signature, {@code htm}/{@code htu},
 * {@code iat} freshness, {@code jti} replay via a built-in cache, {@code ath}, and
 * the {@code cnf.jkt} thumbprint match) and the access token is decoded through
 * the <em>same</em> JWT authentication manager, so the issuer/audience checks and
 * the acr step-up below still apply to DPoP-scheme requests. Two complementary
 * guards ensure a bound token cannot be downgraded to a plain bearer token:
 * <ul>
 *   <li>the framework's own {@code BearerTokenAuthenticationFilter} already
 *       rejects a {@code cnf}-bound token presented under the {@code Bearer}
 *       scheme (RFC 9449 §7.1), so no custom filter is needed for that; and</li>
 *   <li>{@link DpopBoundTokenValidator} (wired into the decoder below) requires
 *       <em>every</em> accepted token to carry {@code cnf.jkt}, so an unbound
 *       token is refused under any scheme and the guarantee does not rest on
 *       Keycloak's client toggle alone.</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /** Authority prefix for the {@code acr} claim, e.g. {@code acr=pro -> ACR_pro}. */
    private static final String ACR_AUTHORITY_PREFIX = "ACR_";

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
            @Value("${app.security.stepup.acr:pro}") String requiredAcrProperty) throws Exception {
        // Trim so a stray-whitespace config value can't silently make the required
        // authority unmatchable (the endpoint would fail closed for everyone).
        String requiredAcr = requiredAcrProperty.strip();
        String stepUpAuthority = ACR_AUTHORITY_PREFIX + requiredAcr;
        http
            .cors(Customizer.withDefaults())
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/server-details").hasAuthority(stepUpAuthority)
                .anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(acrAuthenticationConverter()))
                .accessDeniedHandler(new StepUpAccessDeniedHandler(requiredAcr, stepUpAuthority)));
        return http.build();
    }

    /**
     * Derives authorities from the default scope/role converter and, in addition,
     * maps the access token's {@code acr} claim to an {@code ACR_<value>} authority
     * so authorization rules can require an assurance level. The default scope
     * authorities are kept (not replaced) so a future {@code SCOPE_*} rule still
     * works.
     */
    private JwtAuthenticationConverter acrAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter defaultAuthorities = new JwtGrantedAuthoritiesConverter();
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>(defaultAuthorities.convert(jwt));
            String acr = jwt.getClaimAsString("acr");
            if (acr != null && !acr.isBlank()) {
                authorities.add(new SimpleGrantedAuthority(ACR_AUTHORITY_PREFIX + acr.strip()));
            }
            return authorities;
        });
        return converter;
    }

    /**
     * Decoder that validates the standard claims (signature, issuer, expiry) and,
     * in addition, requires the access token's `aud` to include this API's
     * audience (so tokens minted for other clients in the realm are rejected) and
     * that the token is DPoP-bound ({@code cnf.jkt} present), so an unbound token
     * is never accepted regardless of scheme (see {@link DpopBoundTokenValidator}).
     */
    @Bean
    JwtDecoder jwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
            @Value("${app.security.jwt.audience:nextjs-frontend}") String audience) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(issuerUri).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefaultWithIssuer(issuerUri),
            new AudienceValidator(audience),
            new DpopBoundTokenValidator()));
        return decoder;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000"));
        config.setAllowedMethods(List.of("GET", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        // Let the browser fetch read the RFC 9470 step-up challenge on a 401.
        config.setExposedHeaders(List.of("WWW-Authenticate"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
