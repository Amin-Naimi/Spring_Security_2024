package com.mohamed.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenRepo tokenRepo;

    private void revokeAlllUserTokens(User user) {
        var valideUserToken = tokenRepo.findAllValidTokensByUser(user.getId());
        if (valideUserToken.isEmpty())
            return;
        valideUserToken.forEach(t -> {
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
        String jwt = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.createRefreshToken(user);
        Token token = new Token();
        token.setUser(myUser);
        token.setToken(jwt);
        token.setExpired(false);
        token.setRevoked(false);
        token.setTokenType(TokenType.BEARER);
        tokenRepo.save(token);
        return AuthenticationResponse.builder()
                .accessToken(jwt)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse login(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail(),
                        authenticationRequest.getPassword()));
        User user = new User();
        user = userRepo.findByEmail(authenticationRequest.getEmail()).orElseThrow(() -> new UsernameNotFoundException("USER NOT FOUND"));
        String jwt = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.createRefreshToken(user);
        Token token = new Token();
        token.setUser(user);
        token.setToken(jwt);
        token.setExpired(false);
        token.setRevoked(false);
        token.setTokenType(TokenType.BEARER);
        revokeAlllUserTokens(user);
        tokenRepo.save(token);
        return AuthenticationResponse.builder()
                .accessToken(jwt)
                .refreshToken(refreshToken)
                .build();
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userName;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userName = jwtService.extractUserName(refreshToken);

        // Verifier si l'user name n'est pas null et si l' user n'est pas encore authentifier
        if(userName != null){
            // Recuprer le user depuis la base (existe ou non)
            var userDetails = this.userRepo.findByEmail(userName).orElseThrow();

            if(jwtService.isTokenValide(refreshToken, userDetails)){
                var accesToken = jwtService.generateAccessToken(userDetails);
                Token token = new Token();
                token.setUser(userDetails);
                token.setToken(accesToken);
                token.setExpired(false);
                token.setRevoked(false);
                token.setTokenType(TokenType.BEARER);
                revokeAlllUserTokens(userDetails);
                tokenRepo.save(token);
                var authResponce = AuthenticationResponse.builder()
                        .accessToken(accesToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponce);

            }
        }
    }
}
