package com.mohamed.security.auth;

import com.mohamed.security.Security.JwtService;
import com.mohamed.security.dto.auth.AuthenticationRequest;
import com.mohamed.security.dto.auth.AuthenticationResponse;
import com.mohamed.security.dto.auth.RegisterRequest;
import com.mohamed.security.user.Role;
import com.mohamed.security.user.User;
import com.mohamed.security.user.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest registerRequest) {
        User user = new User();
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setRole(Role.ADMIN);
        userRepo.save(user);
        String jwt = jwtService.generateToken(user);
        return new AuthenticationResponse(jwt);
    }

    public AuthenticationResponse login(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail(),
                        authenticationRequest.getPassword()));
    User user = new User();
    user = userRepo.findByEmail(authenticationRequest.getEmail()).orElseThrow(()-> new UsernameNotFoundException("USER NOT FOUND"));
        String jwt = jwtService.generateToken(user);
        return new AuthenticationResponse(jwt);
    }
}
