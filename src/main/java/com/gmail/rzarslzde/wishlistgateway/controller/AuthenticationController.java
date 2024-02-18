package com.gmail.rzarslzde.wishlistgateway.controller;

import com.gmail.rzarslzde.wishlistgateway.dto.AuthenticationRequestDTO;
import com.gmail.rzarslzde.wishlistgateway.dto.AuthenticationResponseDTO;
import com.gmail.rzarslzde.wishlistgateway.dto.RegisterRequestDTO;
import com.gmail.rzarslzde.wishlistgateway.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<AuthenticationResponseDTO> register(@RequestBody RegisterRequestDTO registerRequestDTO) {
        return ResponseEntity.ok(authenticationService.register(registerRequestDTO));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponseDTO> authenticate(@RequestBody AuthenticationRequestDTO authenticationRequestDTO) {
        return ResponseEntity.ok(authenticationService.authenticate(authenticationRequestDTO));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        authenticationService.refreshToken(request, response);
    }
}
