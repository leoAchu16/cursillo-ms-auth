package org.cursillo.auth.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Acceso al usuario autenticado de la petición actual (cargado por JwtAuthenticationFilter).
 */
@Component
public class UsuarioActual {

    /** Id del usuario logueado (claim del JWT), o null si no hay autenticación. */
    public Integer id() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof AuthenticatedUser user) {
            return user.id();
        }
        return null;
    }

    public boolean tieneRol(String rol) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return false;
        String autoridad = "ROLE_" + rol;
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(autoridad::equals);
    }

    public boolean esSecretaria() {
        return tieneRol("SECRETARIA");
    }

    /** true si el id corresponde al usuario logueado. */
    public boolean esElMismo(Integer idUsuario) {
        Integer id = id();
        return id != null && id.equals(idUsuario);
    }
}
