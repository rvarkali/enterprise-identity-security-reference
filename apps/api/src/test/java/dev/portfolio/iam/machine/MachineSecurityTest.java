package dev.portfolio.iam.machine;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;
import org.junit.jupiter.api.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import static org.junit.jupiter.api.Assertions.*;

class MachineSecurityTest {
  static RSAKey key;
  NimbusJwtDecoder decoder;
  @BeforeAll static void keys() throws Exception { key = new RSAKeyGenerator(2048).generate(); }
  @BeforeEach void setup() throws Exception {
    decoder = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).signatureAlgorithm(SignatureAlgorithm.RS256).build();
    MachineSecurityConfiguration.configure(decoder, "https://issuer.test", "service-subject");
  }
  static JWTClaimsSet.Builder claims() {
    return new JWTClaimsSet.Builder().issuer("https://issuer.test").subject("service-subject")
        .audience("iam-machine-api").issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(300)))
        .claim("azp", "iam-policy-reader").claim("typ", "Bearer")
        .claim("resource_access", Map.of("iam-policy-reader", Map.of("roles", List.of("policy.read"))));
  }
  static String signed(JWTClaimsSet claims, RSAKey signer, JWSAlgorithm algorithm) throws Exception {
    var jwt = new SignedJWT(new JWSHeader(algorithm), claims);
    jwt.sign(new RSASSASigner(signer)); return jwt.serialize();
  }
  @Test void validMachineToken() throws Exception {
    assertEquals("service-subject", decoder.decode(signed(claims().build(), key, JWSAlgorithm.RS256)).getSubject());
  }
  @Test void rejectsInvalidClaims() throws Exception {
    List<Consumer<JWTClaimsSet.Builder>> changes = List.of(
        b -> b.issuer("https://wrong"), b -> b.expirationTime(null),
        b -> b.expirationTime(Date.from(Instant.now().minusSeconds(1))),
        b -> b.notBeforeTime(Date.from(Instant.now().plusSeconds(60))),
        b -> b.issueTime(Date.from(Instant.now().plusSeconds(60))), b -> b.issueTime(null),
        b -> b.audience("wrong"), b -> b.audience("iam-api"),
        b -> b.audience(List.of("iam-machine-api", "iam-api")),
        b -> b.claim("azp", "iam-web"), b -> b.subject("wrong"), b -> b.subject(null),
        b -> b.claim("typ", "ID"), b -> b.claim("resource_access", Map.of()),
        b -> b.claim("resource_access", Map.of("iam-policy-reader", Map.of("roles", List.of("policy.read", "admin")))),
        b -> b.claim("resource_access", Map.of("iam-policy-reader", Map.of("roles", "policy.read"))),
        b -> b.claim("realm_access", Map.of("roles", List.of("admin"))));
    for (var change : changes) {
      var builder = claims(); change.accept(builder);
      String token = signed(builder.build(), key, JWSAlgorithm.RS256);
      assertThrows(JwtException.class, () -> decoder.decode(token));
    }
  }
  @Test void signatureAndAlgorithmRequired() throws Exception {
    for (String token : List.of(new PlainJWT(claims().build()).serialize(),
        signed(claims().build(), new RSAKeyGenerator(2048).generate(), JWSAlgorithm.RS256),
        signed(claims().build(), key, JWSAlgorithm.RS512))) {
      assertThrows(JwtException.class, () -> decoder.decode(token));
    }
  }
  @Test void unconfiguredSubjectFailsClosed() throws Exception {
    MachineSecurityConfiguration.configure(decoder, "https://issuer.test", "");
    assertThrows(JwtException.class, () -> decoder.decode(signed(claims().build(), key, JWSAlgorithm.RS256)));
    assertThrows(IllegalStateException.class, () -> new MachineSecurityConfiguration()
        .machineJwtDecoder("https://issuer.test", "https://issuer.test/certs", "", true));
  }
}
