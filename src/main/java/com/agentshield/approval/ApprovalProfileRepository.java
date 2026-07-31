package com.agentshield.approval;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApprovalProfileRepository extends JpaRepository<ApprovalProfile, Long> {

    List<ApprovalProfile> findByEnabledTrueOrderByPriorityDesc();

    List<ApprovalProfile> findByPriorityAndEnabledTrue(int priority);

    boolean existsByName(String name);
}
