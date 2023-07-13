package com.example.mediumreactivewebflux5security_db.repository;

import com.example.mediumreactivewebflux5security_db.model.User;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

public interface ReactiveUserRepository extends ReactiveMongoRepository<User, String> {
    Mono<UserDetails> findByUsername(String username);
}
