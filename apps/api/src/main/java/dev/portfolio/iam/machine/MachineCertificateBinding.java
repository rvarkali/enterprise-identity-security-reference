package dev.portfolio.iam.machine;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/** Trust comes from the dedicated Tomcat connector, never from HTTP identity headers. */
final class MachineCertificateBinding implements AuthorizationManager<RequestAuthorizationContext> {
  private final String subject;
  private final String uri;

  MachineCertificateBinding(String subject, String uri, boolean enabled) {
    this.subject = subject;
    this.uri = uri;
    if ((!uri.isBlank() && !validUri(uri)) || (enabled && (subject.isBlank() || uri.isBlank())))
      throw new IllegalStateException("Machine certificate URI and service-account subject required");
  }

  private static boolean validUri(String value) {
    try {
      URI parsed = URI.create(value);
      return parsed.isAbsolute() && parsed.getFragment() == null && !value.isBlank();
    } catch (IllegalArgumentException e) { return false; }
  }

  @Override
  public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
    boolean allowed = false;
    try {
      var request = context.getRequest();
      if (subject.isBlank() || uri.isBlank()
          || !(request.getAttribute(MachineListenerGuard.TRANSPORT) instanceof MachineListenerGuard.Transport t)
          || !t.machine()) return new AuthorizationDecision(false);
      if (!(authentication.get() instanceof JwtAuthenticationToken auth) || !auth.isAuthenticated())
        return new AuthorizationDecision(false);
      var jwt = auth.getToken();
      if (!subject.equals(jwt.getSubject()) || !"iam-policy-reader".equals(jwt.getClaims().get("azp"))
          || !(jwt.getClaims().get("resource_access") instanceof Map<?, ?> clients)
          || !(clients.get("iam-policy-reader") instanceof Map<?, ?> client)
          || !List.of("policy.read").equals(client.get("roles"))) return new AuthorizationDecision(false);
      // Jakarta Servlet standard attribute populated by Tomcat following mandatory mTLS verification.
      if (!(request.getAttribute("jakarta.servlet.request.X509Certificate") instanceof X509Certificate[] chain)
          || chain.length == 0) return new AuthorizationDecision(false);
      for (X509Certificate certificate : chain) certificate.checkValidity();
      var sans = chain[0].getSubjectAlternativeNames();
      if (sans == null) return new AuthorizationDecision(false);
      int identities = 0;
      boolean match = false;
      for (var san : sans) {
        if (san.size() < 2) return new AuthorizationDecision(false);
        if (Integer.valueOf(6).equals(san.get(0))) {
          identities++;
          match = uri.equals(san.get(1));
        }
      }
      // Exactly one URI SAN: no CN fallback, duplicate or competing URI identities.
      allowed = identities == 1 && match;
    } catch (Exception e) {
      // Malformed certificates/claims fail closed without logging credentials or certificate contents.
    }
    return new AuthorizationDecision(allowed);
  }
}
