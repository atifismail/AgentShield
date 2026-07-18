package com.agentshield.policy;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface PolicyOverrideRepository extends JpaRepository<PolicyOverride, Long> {

    @Query("select o from PolicyOverride o where o.enabled = true order by o.priority asc, o.id asc")
    List<PolicyOverride> findActiveOrderByPriority();

    List<PolicyOverride> findAllByOrderByPriorityAscIdAsc();
}
