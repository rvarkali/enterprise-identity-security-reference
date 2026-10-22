package dev.portfolio.iam.machine;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class MachineSecurityConfiguration {
  @Bean("machineJwtDecoder")
  JwtDecoder machineJwtDecoder(@Value("${iam.issuer-uri}") String issuer,
      @Value("${iam.jwk-set-uri}") String jwks,
      @Value("${iam.machine.subject:}") String subject,
      @Value("${iam.machine.tls.enabled:false}") boolean enabled) {
    if (enabled && subject.isBlank()) throw new IllegalStateException("Machine service-account subject required");
    var decoder = NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).build();
    configure(decoder, issuer, subject);
    return decoder;
  }

  static void configure(NimbusJwtDecoder decoder, String issuer, String subject) {
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
        new JwtIssuerValidator(issuer), new JwtTimestampValidator(Duration.ZERO), token -> {
          try {
            Instant now = Instant.now();
            Object resources = token.getClaims().get("resource_access");
            Object realm = token.getClaims().get("realm_access");
            boolean roles = resources instanceof Map<?, ?> clients
                && clients.keySet().equals(java.util.Set.of("iam-policy-reader"))
                && clients.get("iam-policy-reader") instanceof Map<?, ?> client
                && client.get("roles") instanceof List<?> permissions
                && permissions.equals(List.of("policy.read"));
            boolean noRealmRoles = realm == null || (realm instanceof Map<?, ?> r
                && (!r.containsKey("roles") || r.get("roles") instanceof List<?> list && list.isEmpty()));
            boolean valid = !subject.isBlank() && subject.equals(token.getSubject())
                && token.getAudience().equals(List.of("iam-machine-api"))
                && "iam-policy-reader".equals(token.getClaims().get("azp"))
                && "Bearer".equals(token.getClaims().get("typ"))
                && token.getExpiresAt() != null && token.getIssuedAt() != null
                && token.getExpiresAt().isAfter(now) && !token.getIssuedAt().isAfter(now)
                && token.getExpiresAt().isAfter(token.getIssuedAt()) && roles && noRealmRoles;
            return valid ? OAuth2TokenValidatorResult.success() : invalid();
          } catch (RuntimeException e) { return invalid(); }
        }));
  }

  private static OAuth2TokenValidatorResult invalid() {
    return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Machine token rejected", null));
  }

  @Bean
  MachineCertificateBinding machineCertificateBinding(
      @Value("${iam.machine.subject:}") String subject,
      @Value("${iam.machine.certificate-uri:}") String uri,
      @Value("${iam.machine.tls.enabled:false}") boolean enabled) {
    return new MachineCertificateBinding(subject, uri, enabled);
  }

  @Bean
  @Order(1)
  SecurityFilterChain machineSecurityFilterChain(HttpSecurity http,
      @Qualifier("machineJwtDecoder") JwtDecoder decoder, MachineCertificateBinding binding) throws Exception {
    return http.securityMatcher("/api/machine", "/api/machine/**")
        .addFilterBefore((request, response, chain) -> {
          Object transport = request.getAttribute(MachineListenerGuard.TRANSPORT);
          if (!(transport instanceof MachineListenerGuard.Transport t) || !t.machine()) {
            ((jakarta.servlet.http.HttpServletResponse) response).setStatus(403);
            return;
          }
          chain.doFilter(request, response);
        }, org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter.class)
        .csrf(csrf -> csrf.disable())
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .oauth2ResourceServer(o -> o.jwt(j -> j.decoder(decoder)
            .jwtAuthenticationConverter(jwt -> new JwtAuthenticationToken(jwt, List.of()))))
        // Authorization requires both authenticated JWT identity and the container-verified certificate.
        .authorizeHttpRequests(a -> a.anyRequest().access(binding))
        .build();
  }
}
