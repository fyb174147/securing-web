package com.example.securingweb.repository;

import com.example.securingweb.model.Authority;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Set;

public interface AuthorityRepository extends JpaRepository<Authority, Long> {
    Set<Authority> findByUsername(String username);
}