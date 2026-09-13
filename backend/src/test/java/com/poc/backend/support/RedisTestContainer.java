package com.poc.backend.support;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * A single shared Redis container for the integration tests, following the
 * Testcontainers "singleton container" pattern: started once per JVM and reused
 * across test classes (JUnit never stops it; Ryuk reaps it after the run). Since
 * iteration 4 the resource server needs Redis for the DPoP {@code jti} replay
 * check, so every DPoP-exercising integration test points {@code spring.data.redis.*}
 * at this instance via {@link #registerProperties}.
 */
public final class RedisTestContainer {

    @SuppressWarnings("resource") // shared for the JVM lifetime; reaped by Ryuk
    public static final GenericContainer<?> INSTANCE =
        new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

    static {
        INSTANCE.start();
    }

    private RedisTestContainer() {
    }

    /** Points {@code spring.data.redis.host/port} at this container. */
    public static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", INSTANCE::getHost);
        registry.add("spring.data.redis.port", () -> INSTANCE.getMappedPort(6379));
    }
}
