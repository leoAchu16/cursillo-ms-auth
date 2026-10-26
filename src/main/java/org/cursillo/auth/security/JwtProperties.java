package org.cursillo.auth.security;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "security.jwt")
public record JwtProperties(
        @NotBlank String secret,
        @NotBlank String algorithm,
        @Min(1) long expirationMinutes,
        @NotBlank String issuer,
        @Valid Claim claim) {

    public record Claim(@NotBlank String user, @NotBlank String roles) {}
}
