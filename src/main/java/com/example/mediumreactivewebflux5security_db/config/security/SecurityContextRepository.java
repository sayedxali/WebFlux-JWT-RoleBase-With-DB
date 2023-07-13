package com.example.mediumreactivewebflux5security_db.config.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * <span style='color:white'>Step 6: Implement the {@link ServerSecurityContextRepository}.</span>
 * <p>An implementation of the {@link ServerSecurityContextRepository} interface that retrieves the {@link SecurityContext} object for the current request based on a JWT token in the request header.</p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityContextRepository implements ServerSecurityContextRepository {

    private final AuthenticationManager authenticationManager;

    /**
     * Not implemented. Throws an {@link UnsupportedOperationException}.
     *
     * @param exchange the {@link ServerWebExchange} object
     * @param context  the {@link SecurityContext} object to save
     * @return a {@link Mono} object
     * @throws UnsupportedOperationException always
     */
    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        log.warn("Not supported yet.");
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Retrieves the {@link SecurityContext} object for the current request based on a JWT token in the request header.
     *
     * @param exchange the {@link ServerWebExchange} object
     * @return a {@link Mono} object containing the {@link SecurityContext} object
     */
    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION);
        return Mono.justOrEmpty(authHeader)
                .filter(header -> header.startsWith("Bearer "))
                .flatMap(header -> {
                            String token = header.substring(7);
                            log.info("token from `header.substring(7)` : {}", token);
                            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(token, token);
                            return authenticationManager.authenticate(authentication)
                                    .map(SecurityContextImpl::new);
                        }
                );
    }

    /*
     * Detailed explanation:
     * The SecurityContextRepository class is an implementation of the ServerSecurityContextRepository interface, which is responsible for
     * storing and retrieving the SecurityContext object for the current request.
     * The SecurityContextRepository constructor takes an AuthenticationManager object as argument.
     * The AuthenticationManager object is responsible for authenticating the user based on the JWT token.
     * The save method is not implemented and throws an UnsupportedOperationException. This is because //TODO: make an explanation on this
     * The load method retrieves the JWT token from the Authorization header in the HTTP request, extracts the token, and passes it to the
     * AuthenticationManager object for authentication.
     * If the token is valid, the AuthenticationManager returns an Authentication object, which is used to create a new SecurityContextImpl object
     * and returned wrapped in a Mono object.
     * If the token is not valid, the AuthenticationManager returns an error, and the load method returns an empty Mono object.
     */
}
