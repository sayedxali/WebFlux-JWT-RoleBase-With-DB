package com.example.mediumreactivewebflux5security_db.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

/**
 * <span style='color:white'>Step 4: Configures security for the webflux application.</span>
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class WebfluxSecurityConfiguration {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    /**
     * Configures the security web filter for the application.
     *
     * <p>This method creates a {@link SecurityWebFilterChain} bean that defines the security rules for the application. The following steps are performed:</p>
     *
     * <ol>
     *     <li>Disable CSRF protection by calling the {@link ServerHttpSecurity#csrf() csrf()} method of the {@link ServerHttpSecurity} object.</li>
     *
     *     <li>Configure exception handling by calling the {@link ServerHttpSecurity#exceptionHandling() exceptionHandling()} method of the {@link ServerHttpSecurity} object.
     *         <ul>
     *             <li>Set the authentication entry point to return a 401 Unauthorized response.</li>
     *             <li>Set the access denied handler to return a 403 Forbidden response.</li>
     *         </ul>
     *     </li>
     *
     *     <li>Set the authentication manager by calling the {@link ServerHttpSecurity#authenticationManager() authenticationManager()} method of the {@link ServerHttpSecurity} object.
     *         <p>Note that in reactive webflux with JWT, we use a {@link AuthenticationManager custom class} that implements {@link ReactiveAuthenticationManager ReactiveAuthenticationManager} for authenticating users in a reactive way rather then using {@link AuthenticationManager AuthenticationManager} in Regular blocking way.</p>
     *     </li>
     *
     *     <li>Set the security context repository by calling the {@link ServerHttpSecurity#securityContextRepository() securityContextRepository()} method of the {@link ServerHttpSecurity} object. A {@link SecurityContextRepository custom class} that implements {@link ServerSecurityContextRepository}.
     *         <p>In reactive webflux with JWT, we use the {@link ServerSecurityContextRepository} to store and retrieve the {@link SecurityContext} for the current request, which contains the authentication information for the current user.</p>
     *         <p>The reason we need to use {@link ServerSecurityContextRepository} is that in reactive webflux, we cannot rely on the thread-local storage that is used in traditional blocking applications to store the SecurityContext. Instead, we need to use a {@link ServerSecurityContextRepository} that can store and retrieve the SecurityContext in a reactive-friendly way.</p>
     *     </li>
     *
     *     <li>Configure authorization rules by calling the {@link ServerHttpSecurity#authorizeExchange() authorizeExchange()} method of the {@link ServerHttpSecurity} object.
     *         <p>Use the {@link AuthorizeExchangeSpec#pathMatchers(String...)} method to specify the URLs that should be allowed without authentication.</p>
     *         <p>Use the {@link AuthorizeExchangeSpec#anyExchange()} method to specify that all other URLs require authentication.</p>
     *         <p>Use the {@link AuthorizeExchangeSpec.Access#authenticated()} method to specify that authentication is required for the URLs specified by {@link AuthorizeExchangeSpec#anyExchange()}.</p>
     *     </li>
     * </ol>
     *
     * @param httpSecurity the HTTP security configuration
     * @return the security web filter chain
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity) {
        httpSecurity.csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint((serverWebExchange, exception) ->
                        Mono.fromRunnable(() -> serverWebExchange.getResponse().setStatusCode(UNAUTHORIZED))
                ).accessDeniedHandler((serverWebExchange, deniedException) ->
                        Mono.fromRunnable(() -> serverWebExchange.getResponse().setStatusCode(FORBIDDEN))
                ).and()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange(authorizeExchangeSpec ->
                        authorizeExchangeSpec
                                .pathMatchers("/login").permitAll()
                                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                                .anyExchange().authenticated());
        return httpSecurity.build();
    }

}
