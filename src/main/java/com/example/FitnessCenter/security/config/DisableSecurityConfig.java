package com.example.FitnessCenter.security.config;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * ❌ Security Disable Configuration
 *
 * This configuration disables Spring Security entirely.
 *
 * ✅ It is activated **only when** the property `fitnessapp.security.enable=false`
 * is set in `application.properties` or through the active profile's config.
 *
 * ⚠️ Use this configuration strictly for development or testing purposes
 * where login and authentication are not needed.
 *
 * 💡 In production, set `fitnessapp.security.enable=true` to enable JWT or other
 * authentication mechanisms.
 */

@Configuration
@ConditionalOnProperty(name = "fitnessapp.security.enable", havingValue = "false")
public class DisableSecurityConfig {

    @PostConstruct
    public void logWarning() {
        System.out.println("⚠️  WARNING: Security is DISABLED for development/testing purposes.");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll()
                );

        return http.build();
    }

}
