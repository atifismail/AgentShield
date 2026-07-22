package com.agentshield.dlp;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface ClassificationProfileRepository extends JpaRepository<ClassificationProfile, Long> {

    @Query("select p from ClassificationProfile p where p.enabled = true order by p.priority asc, p.id asc")
    List<ClassificationProfile> findActiveOrderByPriority();

    default Optional<ClassificationProfile> findFirstActive() {
        List<ClassificationProfile> active = findActiveOrderByPriority();
        return active.isEmpty() ? Optional.empty() : Optional.of(active.get(0));
    }

    List<ClassificationProfile> findAllByOrderByPriorityAscIdAsc();
}
