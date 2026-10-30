package org.cursillo.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header != null && header.startsWith("Bearer ")) {
            try {
                Claims claims = jwtService.validar(header.substring(7));

                List<SimpleGrantedAuthority> authorities = jwtService.roles(claims).stream()
                        .map(rol -> new SimpleGrantedAuthority("ROLE_" + rol))
                        .toList();

                AuthenticatedUser principal =
                        new AuthenticatedUser(jwtService.idUsuario(claims), claims.getSubject());

                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken(principal, null, authorities));

            } catch (JwtException | IllegalArgumentException e) {
                log.debug("Token rechazado: {}", e.getClass().getSimpleName());
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(request, response);
    }
}