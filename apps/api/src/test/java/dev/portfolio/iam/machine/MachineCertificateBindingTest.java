package dev.portfolio.iam.machine;

import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MachineCertificateBindingTest {
  static final String ID = "urn:iam:policy-reader";
  static JwtAuthenticationToken authentication(String subject, String client, List<String> roles) {
    return new JwtAuthenticationToken(Jwt.withTokenValue("offline-test").header("alg", "RS256")
        .subject(subject).claim("azp", client)
        .claim("resource_access", Map.of("iam-policy-reader", Map.of("roles", roles)))
        .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build(), List.of());
  }
  static boolean allowed(X509Certificate[] certificates, String subject, String client, List<String> roles, boolean machine) {
    var request = new MockHttpServletRequest();
    request.setAttribute(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(machine));
    if (certificates != null) request.setAttribute("jakarta.servlet.request.X509Certificate", certificates);
    return new MachineCertificateBinding("service-subject", ID, true)
        .check(() -> authentication(subject, client, roles), new RequestAuthorizationContext(request)).isGranted();
  }
  static boolean allowed(X509Certificate cert) {
    return allowed(new X509Certificate[]{cert}, "service-subject", "iam-policy-reader", List.of("policy.read"), true);
  }
  @Test void sanIdentityIsExactAndUnambiguous() throws Exception {
    var cert = mock(X509Certificate.class);
    when(cert.getSubjectAlternativeNames()).thenReturn(List.of(List.of(6, ID)));
    assertTrue(allowed(cert));
    for (Collection<List<?>> sans : List.<Collection<List<?>>>of(
        List.of(), List.of(List.of(2, "policy-reader")),
        List.of(List.of(6, "urn:iam:other")),
        List.of(List.of(6, ID), List.of(6, ID)),
        List.of(List.of(6, ID), List.of(6, "urn:iam:other")))) {
      when(cert.getSubjectAlternativeNames()).thenReturn(sans);
      assertFalse(allowed(cert));
    }
    when(cert.getSubjectAlternativeNames()).thenReturn(null);
    assertFalse(allowed(cert));
  }
  @Test void validityAndIdentityMismatchDenied() throws Exception {
    var cert = mock(X509Certificate.class);
    when(cert.getSubjectAlternativeNames()).thenReturn(List.of(List.of(6, ID)));
    var chain = new X509Certificate[]{cert};
    assertFalse(allowed(null, "service-subject", "iam-policy-reader", List.of("policy.read"), true));
    assertFalse(allowed(chain, "other", "iam-policy-reader", List.of("policy.read"), true));
    assertFalse(allowed(chain, "service-subject", "other", List.of("policy.read"), true));
    assertFalse(allowed(chain, "service-subject", "iam-policy-reader", List.of(), true));
    assertFalse(allowed(chain, "service-subject", "iam-policy-reader", List.of("policy.read"), false));
    doThrow(new CertificateExpiredException()).when(cert).checkValidity();
    assertFalse(allowed(cert));
    doThrow(new CertificateNotYetValidException()).when(cert).checkValidity();
    assertFalse(allowed(cert));
  }
  @Test void configurationFailsClosed() {
    assertThrows(IllegalStateException.class, () -> new MachineCertificateBinding("subject", "", true));
    assertThrows(IllegalStateException.class, () -> new MachineCertificateBinding("", ID, true));
    assertThrows(IllegalStateException.class, () -> new MachineCertificateBinding("subject", "relative", true));
    var request = new MockHttpServletRequest();
    assertFalse(new MachineCertificateBinding("", "", false).check(() -> null, new RequestAuthorizationContext(request)).isGranted());
  }
}
