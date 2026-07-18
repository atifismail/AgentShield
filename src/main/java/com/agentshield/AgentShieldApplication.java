package com.agentshield;

import com.agentshield.gateway.OutboundPolicyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(OutboundPolicyProperties.class)
public class AgentShieldApplication {

    public static void main(String[] args) {
        SpringApplication.run(AgentShieldApplication.class, args);
    }
}
