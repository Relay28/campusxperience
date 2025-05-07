package com.wachichaw.backend.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.http.HttpMethod; // Import HttpMethod

import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtRequestFilter jwtRequestFilter;

    public SecurityConfig(JwtRequestFilter jwtRequestFilter) {
        this.jwtRequestFilter = jwtRequestFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .csrf(csrf -> csrf.disable()) // Disable CSRF for stateless APIs
                .authorizeHttpRequests(authorize -> authorize
                        // Public endpoints
                        .requestMatchers("/user/login", "/user/save", "/admin/login", "/user/check-email", "/verify").permitAll()
                        .requestMatchers(HttpMethod.PUT, "/user/update").permitAll() // Review if this should require authentication
                        .requestMatchers("/uploads/**", "/profile_pictures/**").permitAll()

                        // Admin endpoints - Require ROLE_ADMIN
                        .requestMatchers("/admin/**").hasRole("ADMIN") // Manage admins
                        .requestMatchers("/event/**").hasRole("ADMIN") // Manage events
                        .requestMatchers("/ticket/**").hasRole("ADMIN") // Manage tickets
                        .requestMatchers(HttpMethod.GET, "/user/getAll").hasRole("ADMIN") // Get all users
                        .requestMatchers(HttpMethod.DELETE, "/user/delete/**").hasRole("ADMIN") // Delete users

                        // Fallback: Deny any other request by default if not matched above
                        .anyRequest().authenticated() // Other requests need authentication
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // Stateless session management

        // Add the JWT filter before the UsernamePasswordAuthenticationFilter
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:5173")); // Specify allowed origins
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS")); // Allowed HTTP methods
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        // Register CORS for all paths
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // For all paths
        source.registerCorsConfiguration("/uploads/**", configuration); 
        source.registerCorsConfiguration("/profile_pictures/**", configuration);

        return new CorsFilter(source);
    }
}
