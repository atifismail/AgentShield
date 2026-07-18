package com.agentshield.policy;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PolicyRepository extends JpaRepository<Policy, Long> {

    List<Policy> findByNameOrderByVersionDesc(String name);

    Optional<Policy> findFirstByNameAndEnabledTrueOrderByVersionDesc(String name);

    List<Policy> findAllByOrderByNameAscVersionDesc();
}
