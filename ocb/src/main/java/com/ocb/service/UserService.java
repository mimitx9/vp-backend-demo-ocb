package com.ocb.service;

import com.ocb.dto.UserProfileDto;
import com.ocb.model.User;
import com.ocb.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    public UserProfileDto getUserProfile(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        UserProfileDto profile = new UserProfileDto();
        profile.setId(user.getId());
        profile.setUsername(user.getUsername());
        profile.setLastName(user.getLastName());
        profile.setFirstName(user.getFirstName());
        profile.setEmail(user.getEmail());
        return profile;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                new ArrayList<>() // Danh sách quyền, để trống vì chưa cấu hình role
        );
    }
}