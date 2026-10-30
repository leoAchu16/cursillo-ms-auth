package org.cursillo.auth.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cursillo.auth.service.AuthService;
import org.cursillo.auth.service.UsuarioService;
import org.cursillo.commons.dto.LoginRequestDTO;
import org.cursillo.commons.dto.RegistroRequestDTO;
import org.cursillo.commons.dto.TokenResponseDTO;
import org.cursillo.commons.dto.UsuarioResponseDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService service;
    private final UsuarioService usuarioService;

    @SecurityRequirements
    @PostMapping("/login")
    public ResponseEntity<TokenResponseDTO> login(@RequestBody @Valid LoginRequestDTO request) {
        log.info("POST /auth/login - solicitud de autenticacion");
        return ResponseEntity.ok(service.login(request));
    }

    @SecurityRequirements
    @PostMapping("/register")
    public ResponseEntity<UsuarioResponseDTO> register(@RequestBody @Valid RegistroRequestDTO request){
        log.info("POST /auth/register - registro de alumno");
        return ResponseEntity.status(HttpStatus.CREATED).body(usuarioService.registrarAlumno(request));
    }
}