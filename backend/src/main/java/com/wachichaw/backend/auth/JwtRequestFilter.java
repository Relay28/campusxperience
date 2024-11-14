package com.wachichaw.backend.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collections;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.wachichaw.backend.entity.UserEntity;
import com.wachichaw.backend.repository.UserRepo;

import java.io.IOException;
import java.util.Optional;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Autowired
    private UserRepo userRepo; // Inject your UserRepo directly

    public JwtRequestFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @SuppressWarnings("null")
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");
    
        String userId = null;
        String jwt = null;
        
    
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7); // Remove "Bearer " prefix
            userId = jwtUtil.extractUserId(jwt); // Assuming this returns the userId
            System.out.println("User ID extracted from JWT: " + userId);
        }
    
        if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Check if user exists in the database
            Optional<UserEntity> userEntityOptional = userRepo.findById(Integer.parseInt(userId)); // Assuming userId is of type Integer
    
            if (userEntityOptional.isPresent() && jwtUtil.validateToken(jwt, userId)) {
                // If user exists and token is valid, create an authentication object
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userEntityOptional.get(), null, Collections.emptyList()); // No authorities since you mentioned roles are not needed
                SecurityContextHolder.getContext().setAuthentication(authentication);
                System.out.println("User authenticated: " + userId);
            } else {
                System.out.println("Invalid JWT token or user not found");
            }
        } else {
            System.out.println("No JWT token found");
        }
    
        chain.doFilter(request, response); // Continue the filter chain
    }
}



// int userId = Integer.parseInt(username);
//             UserEntity userEntity = new UserEntity();
//             userEntity = userRepo.findById(userId).get();
//             username = userEntity.getName();