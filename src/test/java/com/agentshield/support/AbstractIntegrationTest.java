package com.agentshield.support;

import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.containers.MariaDBContainer;

/**
 * Base class for tests that need a real database. Uses a shared, JVM-wide MariaDB
 * Testcontainer (the "singleton container" pattern: started once in a static initializer,
 * never stopped by a test framework hook) instead of an in-memory database, so tests exercise
 * the same SQL dialect real deployments use. Deliberately does NOT use
 * {@code @Testcontainers}/{@code @Container} — that combination gives each test class its own
 * start/stop lifecycle, and restarting an already-stopped container is unsupported and leaves
 * {@code @ServiceConnection} pointing at a stale, no-longer-valid port. The container is cleaned
 * up by Testcontainers' Ryuk sidecar when the JVM exits.
 *
 * Also activates "demo" — most integration tests rely on the demo mock tools and/or seeded
 * demo agents/tools, both of which are now gated behind that profile (improvement_plan.md #5).
 * A test that specifically needs demo OFF should not extend this base class.
 */
@ActiveProfiles({"test", "demo"})
public abstract class AbstractIntegrationTest {

    @ServiceConnection
    static final MariaDBContainer<?> MARIADB = new MariaDBContainer<>("mariadb:11.4");

    static {
        MARIADB.start();
    }
}
