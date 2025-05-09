package com.ccp.repository;

import com.ccp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    Optional<User> findByAddress(String ciamId);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByAddress(String ciamId);
}