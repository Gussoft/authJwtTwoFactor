package com.gussoft.authjwttwofactor.core.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.gussoft.authjwttwofactor.core.models.emus.Permission.*;
import static com.gussoft.authjwttwofactor.core.models.emus.Role.ADMIN;
import static com.gussoft.authjwttwofactor.core.models.emus.Role.MANAGER;
import static com.gussoft.authjwttwofactor.core.utils.Constrain.PUBLIC;
import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(PUBLIC).permitAll();
                    auth.requestMatchers("/api/v3/admin/**").hasAnyRole(ADMIN.name());
                    auth.requestMatchers(GET, "/api/v3/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name());
                    auth.requestMatchers(POST, "/api/v3/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name());
                    auth.requestMatchers(PUT, "/api/v3/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name());
                    auth.requestMatchers(DELETE, "/api/v3/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name());
                });
        http
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
