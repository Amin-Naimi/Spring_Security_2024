package com.mohamed.security.auth;

import com.mohamed.security.Security.JwtService;
import com.mohamed.security.dto.auth.AuthenticationRequest;
import com.mohamed.security.dto.auth.AuthenticationResponse;
import com.mohamed.security.dto.auth.RegisterRequest;
import com.mohamed.security.token.Token;
import com.mohamed.security.token.TokenRepo;
import com.mohamed.security.token.TokenType;
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
    private final TokenRepo tokenRepo;

    private void revokeAlllUserTokens(User user){
        var valideUserToken = tokenRepo.findAllValidTokensByUser(user.getId());
        if(valideUserToken.isEmpty())
            return;
        valideUserToken.forEach(t->{
            t.setExpired(true);
            t.setRevoked(true);
            tokenRepo.saveAll(valideUserToken);
        });
    }




    public AuthenticationResponse register(RegisterRequest registerRequest) {
        User user = new User();
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setRole(Role.ADMIN);
        User myUser = userRepo.save(user);
        String jwt = jwtService.generateToken(user);
        Token token = new Token();
        token.setUser(myUser);
        token.setToken(jwt);
        token.setExpired(false);
        token.setRevoked(false);
        token.setTokenType(TokenType.BEARER);
        tokenRepo.save(token);
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

        Token token = new Token();
        token.setUser(user);
        token.setToken(jwt);
        token.setExpired(false);
        token.setRevoked(false);
        token.setTokenType(TokenType.BEARER);
        revokeAlllUserTokens(user);
        tokenRepo.save(token);
        return new AuthenticationResponse(jwt);
    }
}
