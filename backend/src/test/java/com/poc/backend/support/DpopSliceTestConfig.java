package com.poc.backend.support;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import com.poc.backend.config.DpopProperties;
import com.poc.backend.dpop.DpopNonceService;
import com.poc.backend.dpop.JtiReplayStore;

/**
 * Supplies the DPoP hardening collaborators that {@code SecurityConfig} needs in
 * the {@code @WebMvcTest} slices, where Redis is not available. The
 * {@link JtiReplayStore} is a simple in-memory set (no Redis, never fails), and
 * {@link DpopNonceService} is the real one over the bound {@link DpopProperties}.
 * The slice tests don't send a {@code DPoP} header, so the filter passes through
 * anyway; these beans exist only so the security filter chain can be built.
 */
@TestConfiguration(proxyBeanMethods = false)
public class DpopSliceTestConfig {

    @Bean
    JtiReplayStore jtiReplayStore() {
        Set<String> seen = ConcurrentHashMap.newKeySet();
        return (jti, ttl) -> seen.add(jti);
    }

    @Bean
    DpopNonceService dpopNonceService(DpopProperties properties) {
        return new DpopNonceService(properties);
    }
}
