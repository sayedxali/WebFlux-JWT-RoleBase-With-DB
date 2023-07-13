package com.example.mediumreactivewebflux5security_db.model;

import com.example.mediumreactivewebflux5security_db.repository.ReactiveUserRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


/**
 * <span style='color:white'>Step 1: Create the {@link User User} model.</span>
 * <p>
 * Create a class called {@link User User} with the @Data, @NoArgsConstructor, @AllArgsConstructor, and @Document annotations.
 * Implement the {@link UserDetails UserDetails} interface to use the {@link User User} class for authentication and authorization.
 * Add fields for userId, username, password, enabled, and roles.
 * Override the {@link UserDetails UserDetails} methods.
 * </p>
 * <p>
 * Now Proceed to create an interface implementing {@link ReactiveMongoRepository ReactiveMongoRepository} for db interaction:
 * {@link ReactiveUserRepository ReactiveUserRepository}.
 * </p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Document
public class User implements UserDetails {

    @Id
    private String userId;

    private String username;
    private String password;

    private Boolean enabled;
    private List<Role> roles;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream().map(
                authority -> new SimpleGrantedAuthority(authority.name())
        ).collect(Collectors.toList());
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

}
