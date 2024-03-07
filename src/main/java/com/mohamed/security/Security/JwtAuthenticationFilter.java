package com.mohamed.security.Security;

import com.mohamed.security.token.TokenRepo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//Every time we got a request the filter is active:
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final AuthentificationUserDetailsService authentificationUserDetailsService;
    private final JwtService jwtService;
    private final TokenRepo tokenReop;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userName;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userName = jwtService.extractUserName(jwt);

        // Verifier si l'user name n'est pas null et si l' user n'est pas encore authentifier
        if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // Recuprer le user depuis la base (existe ou non)
            UserDetails userDetails = this.authentificationUserDetailsService.loadUserByUsername(userName);
            var istokenValid = tokenReop.findByToken(jwt).map(t-> !t.isExpired() && !t.isRevoked()).orElse(false);

            if(jwtService.isTokenValide(jwt, userDetails) && istokenValid){
                // UPDATING THE SECURITY CONTEXTE
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request,response);
    }
}
