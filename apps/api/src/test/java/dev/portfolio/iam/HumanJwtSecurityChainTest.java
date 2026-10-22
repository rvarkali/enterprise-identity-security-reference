package dev.portfolio.iam;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.*;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.annotation.*;
import org.springframework.core.env.MapPropertySource;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** Real production human decoder and filters; no application/data-service bootstrap. */
class HumanJwtSecurityChainTest {
  @Configuration
  @EnableWebMvc
  @EnableWebSecurity
  @Import({SecurityConfig.class, ProtectedHandler.class})
  static class Config {}

  @RestController
  static class ProtectedHandler {
    final AtomicInteger calls = new AtomicInteger();
    boolean authenticated;
    @GetMapping("/api/v1/projects/ac100000-0000-4000-8000-000000000001")
    String read(Authentication authentication) {
      calls.incrementAndGet();
      authenticated = authentication != null && authentication.isAuthenticated()
          && "test-human".equals(authentication.getName());
      return "isolated handler";
    }
  }

  @ParameterizedTest(name = "human JWT: {0}")
  @ValueSource(strings = {"valid", "missing-exp", "expired", "wrong-audience", "wrong-issuer", "invalid-signature"})
  void validatesThroughActualHumanChain(String scenario) throws Exception {
    RSAKey trusted = new RSAKeyGenerator(2048).keyID("isolated-key").generate();
    byte[] publicJwks = new JWKSet(trusted.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
    AtomicInteger jwksRequests = new AtomicInteger();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/jwks", exchange -> {
      jwksRequests.incrementAndGet();
      exchange.getResponseHeaders().set("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, publicJwks.length);
      try (var body = exchange.getResponseBody()) { body.write(publicJwks); }
      finally { exchange.close(); }
    });
    server.start();
    var context = new AnnotationConfigWebApplicationContext();
    try {
      context.setServletContext(new MockServletContext());
      context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("isolated", Map.of(
          "iam.issuer-uri", "https://issuer.invalid/human-test",
          "iam.jwk-set-uri", "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks",
          "iam.audience", "iam-api")));
      context.register(Config.class);
      context.refresh();
      assertInstanceOf(NimbusJwtDecoder.class, context.getBean("jwtDecoder"));
      assertTrue(context.getBeansOfType(javax.sql.DataSource.class).isEmpty());
      var mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
      Instant now = Instant.now();
      var claims = new JWTClaimsSet.Builder()
          .issuer(scenario.equals("wrong-issuer") ? "https://wrong.invalid" : "https://issuer.invalid/human-test")
          .subject("test-human")
          .audience(scenario.equals("wrong-audience") ? "iam-machine-api" : "iam-api")
          .issueTime(Date.from(now.minusSeconds(600)))
          .notBeforeTime(Date.from(now.minusSeconds(600)));
      if (!scenario.equals("missing-exp")) {
        claims.expirationTime(Date.from(scenario.equals("expired") ? now.minusSeconds(180) : now.plusSeconds(600)));
      }
      var token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
          .type(JOSEObjectType.JWT).keyID(trusted.getKeyID()).build(), claims.build());
      RSAKey signer = scenario.equals("invalid-signature") ? new RSAKeyGenerator(2048).generate() : trusted;
      token.sign(new RSASSASigner(signer));
      var response = mvc.perform(get("/api/v1/projects/ac100000-0000-4000-8000-000000000001")
          .header("Authorization", "Bearer " + token.serialize())).andReturn().getResponse();
      boolean allowed = scenario.equals("valid");
      assertEquals(allowed ? 200 : 401, response.getStatus(), scenario);
      var handler = context.getBean(ProtectedHandler.class);
      assertEquals(allowed ? 1 : 0, handler.calls.get(), scenario);
      assertEquals(allowed, handler.authenticated, scenario);
      assertTrue(jwksRequests.get() > 0, "Real local JWKS lookup required");
      if (scenario.equals("missing-exp")) {
        assertTrue(Optional.ofNullable(response.getHeader("WWW-Authenticate")).orElse("")
            .contains("Missing exp claim"), "Required-exp validator must explain rejection");
      }
    } finally {
      context.close();
      server.stop(0);
    }
  }
}
