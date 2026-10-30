package org.cursillo.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cursillo.auth.exception.BadRequestException;
import org.cursillo.auth.security.JwtProperties;
import org.cursillo.auth.security.JwtService;
import org.cursillo.auth.security.UsuarioPrincipal;
import org.cursillo.commons.dto.LoginRequestDTO;
import org.cursillo.commons.dto.TokenResponseDTO;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtProperties props;

    /**
     * Autentica a un usuario y genera un token JWT.
     *
     * @param dto DTO con el email y la contraseña del usuario.
     * @return DTO con el token JWT generado.
     * @throws BadRequestException si el email o la contraseña son nulos o vacíos.
     */
    public TokenResponseDTO login(LoginRequestDTO dto) {
        if (dto.getEmail() == null || dto.getEmail().isBlank()
                || dto.getContrasenha() == null || dto.getContrasenha().isBlank())
            throw new BadRequestException("El email y la contraseña son obligatorios.");

        log.debug("Intento de autenticacion para el usuario {}", dto.getEmail());

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(dto.getEmail(), dto.getContrasenha()));

        UsuarioPrincipal principal = (UsuarioPrincipal) auth.getPrincipal();
        List<String> roles = principal.getAuthorities().stream()
                .map(a -> a.getAuthority().substring("ROLE_".length()))
                .toList();

        String token = jwtService.generarToken(principal.id(), principal.email(), roles);
        log.debug("Token emitido para el usuario con id {}", principal.id());

        return new TokenResponseDTO()
                .accessToken(token)
                .tokenType("Bearer")
                .expiresInSeconds(props.expirationMinutes() * 60);
    }
}