package com.example.mediumreactivewebflux5security_db.config.security;

import com.example.mediumreactivewebflux5security_db.config.jwt.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collection;


/**
 * <span style='color:white'>Step 5: Implement the {@link ReactiveAuthenticationManager}.</span>
 * <p>A reactive implementation of the {@link ReactiveAuthenticationManager} interface that validates JWT tokens and returns an authenticated {@link Authentication} object.</p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationManager implements ReactiveAuthenticationManager {

    private final JWTUtil jwtUtil;
    private final ReactiveUserDetailsService userDetailsService;

    /**
     * Authenticates the JWT token in the input {@link Authentication} object and returns an authenticated {@link Authentication} object.
     *
     * @param authentication the input {@link Authentication} object containing the JWT token
     * @return a {@link Mono} object containing the authenticated {@link Authentication} object
     * @throws RuntimeException if the user is not found
     */
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String token = authentication.getCredentials().toString();
        String username = jwtUtil.extractUsername(token);
        return userDetailsService.findByUsername(username)
                .map(userDetails -> {
                    Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
                    return new UsernamePasswordAuthenticationToken(
                            username,
                            token,
                            authorities
                    );
                })
                .map(authenticationToken -> (Authentication) authenticationToken)
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")));
    }

    /*
    * Detailed explanation:
    * The `AuthenticationManager` class is a reactive implementation of the `ReactiveAuthenticationManager` interface,
    * which is responsible for validating JWT tokens and returning an `Authentication` object if the token is valid.
    * The `authenticate` method takes an `Authentication` object as input and returns a `Mono<Authentication>` object as output.
    * The input `Authentication` object contains the JWT token to be validated, while the output `Mono<Authentication>` object contains the authenticated
    *  `Authentication` object.
    * The method first extracts the JWT token from the input `Authentication` object and extracts the username from the token using the `JWTUtil` object.
    * It then calls the `findByUsername` method of the `ReactiveUserDetailsService` object to load the user details for the given username. If the user is found, the method creates a `UsernamePasswordAuthenticationToken` object using the username, token, and granted authorities from the user details.
    * The method then returns the `UsernamePasswordAuthenticationToken` object wrapped in a `Mono` object.
    * If the user is not found, the method returns a `Mono` object with an error.
    */
}
