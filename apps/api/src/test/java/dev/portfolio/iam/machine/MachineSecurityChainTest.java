package dev.portfolio.iam.machine;

import dev.portfolio.iam.SecurityConfig;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = MachineSecurityChainTest.Routes.class, properties = {
    "iam.machine.subject=service-subject", "iam.machine.certificate-uri=urn:iam:policy-reader"})
@Import({SecurityConfig.class, MachineSecurityConfiguration.class, MachineSecurityChainTest.Config.class, MachineSecurityChainTest.Routes.class, MachinePolicyController.class})
class MachineSecurityChainTest {
  static RSAKey key;
  static { try { key = new RSAKeyGenerator(2048).generate(); } catch (Exception e) { throw new ExceptionInInitializerError(e); } }
  @Autowired MockMvc mvc;
  @RestController static class Routes {
    @GetMapping({"/human-test", "/api/machine/test"}) String read() { return "must not reach machine handler"; }
  }
  @Configuration static class Config {
    // Use production human chain; replace only its remote key source for offline signed tests.
    @Bean static org.springframework.beans.factory.config.BeanPostProcessor decoders() {
      return new org.springframework.beans.factory.config.BeanPostProcessor() {
        @Override public Object postProcessAfterInitialization(Object bean, String name) {
          if (!(bean instanceof JwtDecoder)) return bean;
          try {
            var decoder = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build();
            if (name.equals("machineJwtDecoder")) MachineSecurityConfiguration.configure(decoder, "https://issuer.test", "service-subject");
            else decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer("https://issuer.test"), jwt -> jwt.getAudience().contains("iam-api")
                    ? org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success()
                    : org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.failure(new org.springframework.security.oauth2.core.OAuth2Error("invalid_token"))));
            return decoder;
          } catch (Exception e) { throw new IllegalStateException(e); }
        }
      };
    }
  }
  String token(boolean machine) throws Exception {
    var claims = MachineSecurityTest.claims();
    if (!machine) claims.audience("iam-api").claim("azp", "iam-web");
    return MachineSecurityTest.signed(claims.build(), key, JWSAlgorithm.RS256);
  }
  @Test void machineRequestsAlwaysFailClosed() throws Exception {
    mvc.perform(get("/api/machine/test").requestAttr(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(true)))
        .andExpect(status().isUnauthorized());
    mvc.perform(get("/api/machine/test").requestAttr(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(true))
        .header("Authorization", "Bearer " + token(false))).andExpect(status().isUnauthorized());
    mvc.perform(get("/api/machine/test").requestAttr(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(true))
        .header("Authorization", "Bearer " + token(true))).andExpect(status().isForbidden());
    mvc.perform(get("/api/machine/test").header("Authorization", "Bearer " + token(true)))
        .andExpect(status().isForbidden());
  }
  @Test void certificateBindingRequiredAlongsideSignedToken() throws Exception {
    var cert = org.mockito.Mockito.mock(java.security.cert.X509Certificate.class);
    org.mockito.Mockito.when(cert.getSubjectAlternativeNames())
        .thenReturn(java.util.List.of(java.util.List.of(6, "urn:iam:policy-reader")));
    mvc.perform(get("/api/machine/test")
        .requestAttr(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(true))
        .requestAttr("jakarta.servlet.request.X509Certificate", new java.security.cert.X509Certificate[]{cert})
        .header("Authorization", "Bearer " + token(true))).andExpect(status().isOk());
    org.mockito.Mockito.when(cert.getSubjectAlternativeNames())
        .thenReturn(java.util.List.of(java.util.List.of(6, "urn:iam:other")));
    mvc.perform(get("/api/machine/test")
        .requestAttr(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(true))
        .requestAttr("jakarta.servlet.request.X509Certificate", new java.security.cert.X509Certificate[]{cert})
        .header("Authorization", "Bearer " + token(true))).andExpect(status().isForbidden());
    mvc.perform(get("/api/machine/test")
        .requestAttr(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(true))
        .header("X-SSL-Client-SAN", "urn:iam:policy-reader")
        .header("X-Forwarded-Client-Cert", "urn:iam:policy-reader")
        .header("Authorization", "Bearer " + token(true))).andExpect(status().isForbidden());
  }
  private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder health(
      String method, String bearer, String san, boolean machine) throws Exception {
    var request = org.springframework.test.web.servlet.request.MockMvcRequestBuilders
        .request(org.springframework.http.HttpMethod.valueOf(method), "/api/machine/policy/health")
        .requestAttr(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(machine));
    request.with(r -> { r.setLocalPort(machine ? 8443 : 8080); return r; });
    if (bearer != null) request.header("Authorization", "Bearer " + bearer);
    if (san != null) {
      var cert = org.mockito.Mockito.mock(java.security.cert.X509Certificate.class);
      org.mockito.Mockito.when(cert.getSubjectAlternativeNames())
          .thenReturn(java.util.List.of(java.util.List.of(6, san)));
      request.requestAttr("jakarta.servlet.request.X509Certificate", new java.security.cert.X509Certificate[]{cert});
    }
    return request;
  }
  @Test void policyHealthUsesMachineAuthenticationAndSanitizedResponse() throws Exception {
    mvc.perform(health("GET", token(true), "urn:iam:policy-reader", true))
        .andExpect(status().isOk())
        .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.content().json("{\"status\":\"UP\"}", true))
        .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Cache-Control", "no-store"));
  }
  @Test void policyHealthRejectsInvalidCredentialsAndListener() throws Exception {
    mvc.perform(health("GET", token(true), null, true)).andExpect(status().isForbidden());
    mvc.perform(health("GET", token(true), "urn:iam:other", true)).andExpect(status().isForbidden());
    mvc.perform(health("GET", null, "urn:iam:policy-reader", true)).andExpect(status().isUnauthorized());
    mvc.perform(health("GET", "invalid", "urn:iam:policy-reader", true)).andExpect(status().isUnauthorized());
    mvc.perform(health("GET", token(false), "urn:iam:policy-reader", true)).andExpect(status().isUnauthorized());
    for (var claims : java.util.List.of(
        MachineSecurityTest.claims().audience("wrong"),
        MachineSecurityTest.claims().claim("resource_access",
            java.util.Map.of("iam-policy-reader", java.util.Map.of("roles", java.util.List.of("policy.write")))))) {
      mvc.perform(health("GET", MachineSecurityTest.signed(claims.build(), key, JWSAlgorithm.RS256),
          "urn:iam:policy-reader", true)).andExpect(status().isUnauthorized());
    }
    mvc.perform(health("GET", token(true), "urn:iam:policy-reader", false)
        .header("X-Forwarded-Port", "8443").header("X-Forwarded-Proto", "https"))
        .andExpect(status().isForbidden());
  }
  @Test void policyHealthRejectsUnsupportedMethods() throws Exception {
    for (String method : java.util.List.of("POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")) {
      mvc.perform(health(method, token(true), "urn:iam:policy-reader", true))
          .andExpect(status().isMethodNotAllowed());
    }
  }
  @Test void policyHealthTraceRejectedBySecurityFirewall() throws Exception {
    mvc.perform(health("TRACE", token(true), "urn:iam:policy-reader", true))
        .andExpect(status().isBadRequest());
  }
  @Test void humanChainKeepsItsAudience() throws Exception {
    mvc.perform(get("/human-test").header("Authorization", "Bearer " + token(true))).andExpect(status().isUnauthorized());
    mvc.perform(get("/human-test").header("Authorization", "Bearer " + token(false))).andExpect(status().isOk());
  }
}
