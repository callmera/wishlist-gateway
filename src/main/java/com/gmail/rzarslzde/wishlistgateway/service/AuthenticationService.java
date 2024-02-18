package com.gmail.rzarslzde.wishlistgateway.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gmail.rzarslzde.wishlistgateway.dto.AuthenticationRequestDTO;
import com.gmail.rzarslzde.wishlistgateway.dto.AuthenticationResponseDTO;
import com.gmail.rzarslzde.wishlistgateway.dto.RegisterRequestDTO;
import com.gmail.rzarslzde.wishlistgateway.entity.Token;
import com.gmail.rzarslzde.wishlistgateway.entity.User;
import com.gmail.rzarslzde.wishlistgateway.enums.TokenType;
import com.gmail.rzarslzde.wishlistgateway.repository.TokenRepository;
import com.gmail.rzarslzde.wishlistgateway.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponseDTO register(RegisterRequestDTO registerRequestDTO) {
        var user = User.builder()
                .firstname(registerRequestDTO.getFirstname())
                .lastname(registerRequestDTO.getLastname())
                .email(registerRequestDTO.getEmail())
                .password(passwordEncoder.encode(registerRequestDTO.getPassword()))
                .role(registerRequestDTO.getRole())
                .build();
        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponseDTO.builder()
                .accessToken(jwtToken).refreshToken(refreshToken).build();
    }

    public AuthenticationResponseDTO authenticate(AuthenticationRequestDTO authenticationRequestDTO) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequestDTO.getEmail(),
                        authenticationRequestDTO.getPassword()
                )
        );
        var user = userRepository.findByEmail(authenticationRequestDTO.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponseDTO.builder()
                .accessToken(jwtToken).refreshToken(refreshToken).build();
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            return;
        }

        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.userRepository.findByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                var authResponse = AuthenticationResponseDTO.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    private void saveUserToken(User user, String jwtToke) {
        var token = Token.builder()
                .user(user)
                .token(jwtToke)
                .tokenType(TokenType.BEARER)
                .expired(false).revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
}
