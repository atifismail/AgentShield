package com.agentshield;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class AgentShieldApplication {

    public static void main(String[] args) {
        SpringApplication.run(AgentShieldApplication.class, args);
    }
}
