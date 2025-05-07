package com.wachichaw.backend.auth;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger; // Use SLF4J for logging
import org.slf4j.LoggerFactory; // Use SLF4J for logging
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.wachichaw.backend.entity.AdminUserEntity; // Import AdminUserEntity
import com.wachichaw.backend.entity.UserEntity;
import com.wachichaw.backend.repository.AdminUserRepo; // Import AdminUserRepo
import com.wachichaw.backend.repository.UserRepo;

import java.io.IOException;
import java.util.Collections;
import java.util.List; // Import List
import java.util.Optional;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtRequestFilter.class); // Logger instance

    private final JwtUtil jwtUtil;
    private final UserRepo userRepo;
    private final AdminUserRepo adminUserRepo; // Inject AdminUserRepo

    // Updated constructor to inject both repositories
    @Autowired
    public JwtRequestFilter(JwtUtil jwtUtil, UserRepo userRepo, AdminUserRepo adminUserRepo) {
        this.jwtUtil = jwtUtil;
        this.userRepo = userRepo;
        this.adminUserRepo = adminUserRepo;
    }

    @SuppressWarnings("null")
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");
        String jwt = null;
        String userId = null;
        String role = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            try {
                userId = jwtUtil.extractUserId(jwt);
                // Attempt to extract role - might be null for regular users
                role = jwtUtil.extractRole(jwt);
                log.debug("JWT received. User ID: {}, Role: {}", userId, role); // Use logger

            } catch (ExpiredJwtException e) {
                log.warn("JWT token has expired: {}", e.getMessage()); // Use logger
                // Optionally set response status SC_UNAUTHORIZED here if needed
            } catch (SignatureException e) {
                log.warn("JWT signature validation failed: {}", e.getMessage()); // Use logger
            } catch (MalformedJwtException e) {
                log.warn("JWT token is malformed: {}", e.getMessage()); // Use logger
            } catch (Exception e) {
                log.error("Error processing JWT token: {}", e.getMessage(), e); // Use logger for unexpected errors
            }
        } else {
             log.trace("No JWT token found in Authorization header for request: {}", request.getRequestURI()); // Use logger
        }

        if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Decide which repository to use based on the role claim
            // Use equalsIgnoreCase for case-insensitive role check
            if ("Admin".equals(role)) { 
                 Optional<AdminUserEntity> adminEntityOptional = adminUserRepo.findById(Integer.parseInt(userId));
                 if (adminEntityOptional.isPresent()) {
                     AdminUserEntity admin = adminEntityOptional.get();
                     // No need to call validateToken again if extraction succeeded
                     UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                             admin, null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))); // Assign ROLE_ADMIN
                     SecurityContextHolder.getContext().setAuthentication(authentication);
                     log.info("Admin authenticated: {}", userId); // Use logger
                 } else {
                     log.warn("Admin user not found in database for ID: {}", userId); // Use logger
                 }

            } else { // Assume regular user if role is not ADMIN
                Optional<UserEntity> userEntityOptional = userRepo.findById(Integer.parseInt(userId));
                if (userEntityOptional.isPresent()) {
                    UserEntity user = userEntityOptional.get();
                    // No need to call validateToken again if extraction succeeded
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            user, null, Collections.emptyList()); // No specific roles for regular users yet
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.info("User authenticated: {}", userId); // Use logger
                } else {
                    log.warn("User not found in database for ID: {}", userId); // Use logger
                }
            }
        }

        chain.doFilter(request, response);
    }
}