package dev.portfolio.iam;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
  @Bean
  @Order(2)
  SecurityFilterChain securityFilterChain(HttpSecurity http, @Qualifier("jwtDecoder") JwtDecoder decoder) throws Exception {
    return http
      .csrf(csrf -> csrf.disable()) // Stateless bearer-token API; no cookie-based authentication.
      .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .authorizeHttpRequests(a -> a
        .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**").permitAll()
        .anyRequest().authenticated())
      .oauth2ResourceServer(o -> o.jwt(j -> j.decoder(decoder)))
      .build();
  }

  @Bean
  @Primary
  JwtDecoder jwtDecoder(@Value("${iam.issuer-uri}") String issuer,
                        @Value("${iam.jwk-set-uri}") String jwks,
                        @Value("${iam.audience}") String audience) {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwks).build();
    OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(issuer);
    OAuth2TokenValidator<Jwt> audienceValidator = token ->
      token.getAudience().contains(audience)
        ? org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success()
        : org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.failure(
            new org.springframework.security.oauth2.core.OAuth2Error("invalid_token", "Missing iam-api audience", null));
    // Timestamp validation checks expiry when present; require it independently.
    OAuth2TokenValidator<Jwt> expirationRequired = token ->
      token.getExpiresAt() != null
        ? org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success()
        : org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.failure(
            new org.springframework.security.oauth2.core.OAuth2Error("invalid_token", "Missing exp claim", null));
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(issuerValidator, audienceValidator, expirationRequired));
    return decoder;
  }
}
