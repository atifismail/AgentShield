package com.agentshield.siem;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DetectionRuleRepository extends JpaRepository<DetectionRule, Long> {

    Optional<DetectionRule> findByCode(String code);

    List<DetectionRule> findAllByOrderByCategoryAscCodeAsc();
}
