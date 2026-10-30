package org.cursillo.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;

@Slf4j
@Service
public class JwtService {

    private final JwtProperties props;
    private final SecretKey key;


    /**
     * Constructor de JwtService
     * @param props propiedades de JWT
     */
    public JwtService(JwtProperties props) {
        this.props = props;
        byte[] bytes = Decoders.BASE64.decode(props.secret());
        if(bytes.length < 32)
            throw new IllegalArgumentException("JWT_SECRET debe ser al menos de 32 bytes");
        this.key = Keys.hmacShaKeyFor(bytes);
    }

    public String generarToken(Integer idUsuario, String email, Collection<String> roles) {
        Instant now = Instant.now();
        log.debug("Generando token para usuario con id {}", idUsuario);
        return Jwts.builder()
                .issuer(props.issuer())
                .subject(email)
                .claim(props.claim().user(), idUsuario)
                .claim(props.claim().roles(), roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(props.expirationMinutes(), ChronoUnit.MINUTES)))
                .signWith(key, algoritmo())
                .compact();
    }

    /**
     * Extraer el id del usuario a partir de los claims
     * @param claims claims del token
     * @return id del usuario
     */
    public Integer idUsuario(Claims claims) {
        return claims.get(props.claim().user(), Integer.class);
    }

    /**
     * Validar token y extraer claims
     * @param token token JWT
     * @return claims del token
     */
    public Claims validar(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer(props.issuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Obtener los roles del usuario a partir de los claims
     * @param claims claims del token
     * @return lista de roles
     */
    public List<?> roles(Claims claims) {
        return claims.get(props.claim().roles(), List.class);
    }


    /**
     * Obtener el algoritmo de firma a partir de las propiedades
     * @return algoritmo de firma
     */
    private MacAlgorithm algoritmo() {
        return switch (props.algorithm().toUpperCase()) {
            case "HS256" -> Jwts.SIG.HS256;
            case "HS384" -> Jwts.SIG.HS384;
            case "HS512" -> Jwts.SIG.HS512;
            default -> throw new IllegalArgumentException("Algoritmo no soportado: " + props.algorithm());
        };
    }

}
