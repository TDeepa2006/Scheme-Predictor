
package com.mindfulmetrics.config;

import com.mindfulmetrics.domain.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    SecurityFilterChain chain(
            HttpSecurity http,
            JwtService jwt,
            UserRepository users,
            CorsConfigurationSource corsConfigurationSource
    ) throws Exception {

        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/admin/**").hasRole("HR")
                .requestMatchers("/analytics/org").hasRole("HR")
                .requestMatchers("/analytics/team", "/reports/**")
                    .hasAnyRole("MANAGER", "HR")
                .anyRequest().authenticated()
            )
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint((request, response, ex) ->
                    json(response, 401, "Authentication required")
                )
                .accessDeniedHandler((request, response, ex) ->
                    json(response, 403,
                        "You do not have permission to access this resource")
                )
            )
            .addFilterBefore(
                new JwtAuthFilter(jwt, users),
                UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }

    private static void json(
            jakarta.servlet.http.HttpServletResponse response,
            int status,
            String message
    ) throws java.io.IOException {

        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write(
            "{\"message\":\"" + message + "\"}"
        );
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors-origins:http://localhost:5173}") String origins
    ) {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(
            Arrays.stream(origins.split(","))
                .map(String::trim)
                .toList()
        );

        config.setAllowedMethods(
            List.of("GET", "POST", "PATCH", "OPTIONS", "PUT", "DELETE")
        );

        config.setAllowedHeaders(
            List.of("Authorization", "Content-Type")
        );

        config.setAllowCredentials(false);

        UrlBasedCorsConfigurationSource source =
            new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", config);

        return source;
    }
}
