package com.example.securingweb.service;

import com.example.securingweb.model.User;
import com.example.securingweb.repository.AuthorityRepository;
import com.example.securingweb.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;

    public JpaUserDetailsService(UserRepository userRepository, AuthorityRepository authorityRepository) {
        this.userRepository = userRepository;
        this.authorityRepository = authorityRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. Tìm người dùng
        Optional<User> userOptional = userRepository.findByUsername(username);
        User user = userOptional
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        // 2. Tìm tất cả quyền hạn của người dùng đó
        Set<String> roles = authorityRepository.findByUsername(username).stream()
                .map(authority -> authority.getAuthority())
                .collect(Collectors.toSet());

        // 3. Trả về đối tượng JpaUserDetails với cả user và roles
        return new JpaUserDetails(user, roles);
    }
}