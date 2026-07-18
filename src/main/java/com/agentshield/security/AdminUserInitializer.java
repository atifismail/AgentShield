package com.agentshield.security;

import java.time.Instant;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Creates the initial ADMIN user on first startup if no users exist yet. */
@Component
public class AdminUserInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminUserInitializer.class);

    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final String defaultUsername;
    private final String defaultPassword;

    public AdminUserInitializer(AppUserRepository repository, PasswordEncoder passwordEncoder,
            @Value("${agentshield.security.default-admin-username}") String defaultUsername,
            @Value("${agentshield.security.default-admin-password}") String defaultPassword) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.defaultUsername = defaultUsername;
        this.defaultPassword = defaultPassword;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (repository.count() > 0) {
            return;
        }
        AppUser admin = new AppUser();
        admin.setUsername(defaultUsername);
        admin.setPasswordHash(passwordEncoder.encode(defaultPassword));
        admin.setFullName("Default Administrator");
        admin.setEnabled(true);
        admin.setRoles(Set.of(UserRole.ADMIN));
        admin.setCreatedAt(Instant.now());
        admin.setUpdatedAt(Instant.now());
        repository.save(admin);
        log.warn("Created default admin user '{}'. Change the default password immediately "
                + "(set AGENTSHIELD_ADMIN_PASSWORD before first startup in any non-local environment).",
                defaultUsername);
    }
}
