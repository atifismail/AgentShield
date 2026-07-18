package com.agentshield.agent;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "agents")
@Getter
@Setter
@NoArgsConstructor
public class Agent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(length = 2000)
    private String description;

    private String owner;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AgentStatus status = AgentStatus.ENABLED;

    private String environment;

    /** Comma-separated tool group names this agent may call. Stored as text for portability. */
    @Column(name = "allowed_tool_groups", length = 2000)
    private String allowedToolGroups;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public Set<String> allowedToolGroupSet() {
        Set<String> groups = new LinkedHashSet<>();
        if (allowedToolGroups == null || allowedToolGroups.isBlank()) {
            return groups;
        }
        for (String group : allowedToolGroups.split(",")) {
            String trimmed = group.trim();
            if (!trimmed.isEmpty()) {
                groups.add(trimmed);
            }
        }
        return groups;
    }

    public boolean isEnabled() {
        return status == AgentStatus.ENABLED;
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
