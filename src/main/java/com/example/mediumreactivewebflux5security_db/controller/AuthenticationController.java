package com.example.mediumreactivewebflux5security_db.controller;

import com.example.mediumreactivewebflux5security_db.config.jwt.JWTUtil;
import com.example.mediumreactivewebflux5security_db.dto.AuthRequest;
import com.example.mediumreactivewebflux5security_db.dto.AuthResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

/**
 * <span style='color:white'>Step 7: Create a controller for logging in and getting the JWT token.</span>
 * <p>A Spring {@link RestController} that handles authentication requests. We can also use a service class to make it more readable!</p>
 */
@RestController
@RequiredArgsConstructor
public class AuthenticationController {

    private final JWTUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final ReactiveUserDetailsService userService;

    /**
     * Handles login requests and returns a JWT token for the authenticated user.
     *
     * @param authRequest the {@link AuthRequest} object containing the username and password for the login request
     * @return a {@link Mono} object containing a {@link ResponseEntity} object with the JWT token for the authenticated user
     */
    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@RequestBody AuthRequest authRequest) {
        return userService.findByUsername(authRequest.getUsername())
                .filter(userDetails ->
                        passwordEncoder.matches(
                                authRequest.getPassword(),
                                userDetails.getPassword()
                        )
                ).map(userDetails -> ResponseEntity.ok(new AuthResponse(jwtUtil.generateToken(userDetails))))
                .switchIfEmpty(Mono.just(ResponseEntity.status(UNAUTHORIZED).build()));
    }

}
