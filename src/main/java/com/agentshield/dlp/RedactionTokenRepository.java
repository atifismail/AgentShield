package com.agentshield.dlp;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RedactionTokenRepository extends JpaRepository<RedactionToken, Long> {

    Optional<RedactionToken> findByToken(String token);
}
