package dev.portfolio.iam.machine;

import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.security.KeyStore;
import javax.net.ssl.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.context.AnnotationConfigServletWebServerApplicationContext;
import org.springframework.context.annotation.*;
import org.springframework.core.env.MapPropertySource;
import org.springframework.mock.web.*;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class MachineTlsTest {
  @TempDir static Path temp;
  static Path keys, trust;
  static final String PASSWORD = "test-only-password";

  @BeforeAll static void fixtures() throws Exception {
    keys = temp.resolve("keys.p12"); trust = temp.resolve("trust.p12");
    tool("-genkeypair", "-alias", "test", "-keyalg", "RSA", "-dname", "CN=localhost", "-validity", "2",
        "-ext", "bc=ca:true", "-ext", "san=dns:localhost,ip:127.0.0.1,uri:urn:iam:policy-reader", "-ext", "eku=serverAuth,clientAuth",
        "-keystore", keys.toString(), "-storetype", "PKCS12", "-storepass", PASSWORD);
    Path cert = temp.resolve("test.crt");
    tool("-exportcert", "-alias", "test", "-keystore", keys.toString(), "-storepass", PASSWORD, "-file", cert.toString());
    tool("-importcert", "-noprompt", "-alias", "test", "-keystore", trust.toString(), "-storetype", "PKCS12",
        "-storepass", PASSWORD, "-file", cert.toString());
  }
  static void tool(String... args) throws Exception {
    var command = new java.util.ArrayList<String>();
    command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
    command.addAll(java.util.List.of(args));
    var process = new ProcessBuilder(command).redirectErrorStream(true).start();
    process.getInputStream().readAllBytes();
    assertEquals(0, process.waitFor(), "Test certificate generation failed");
  }

  @Configuration(proxyBeanMethods = false)
  @Import(MachineTlsConfiguration.class)
  static class App {
    @Bean static org.springframework.boot.web.server.WebServerFactoryCustomizerBeanPostProcessor customizers() {
      return new org.springframework.boot.web.server.WebServerFactoryCustomizerBeanPostProcessor();
    }
    @Bean TomcatServletWebServerFactory server() { return new TomcatServletWebServerFactory(0); }
    @Bean ServletRegistrationBean<HttpServlet> routes() {
      return new ServletRegistrationBean<>(new HttpServlet() {
        @Override protected void doGet(HttpServletRequest req, HttpServletResponse res) throws java.io.IOException, ServletException {
          if (req.getServletPath().equals("/forward")) { req.getRequestDispatcher("/api/machine/test").forward(req, res); return; }
          if (req.getServletPath().equals("/api/machine/forward")) { req.getRequestDispatcher("/human").forward(req, res); return; }
          if (req.getServletPath().startsWith("/api/machine/binding")) {
            // Real container certificate and connector evidence; JWT authentication is a test fixture here.
            String identity = req.getServletPath().endsWith("/wrong") ? "urn:iam:other" : "urn:iam:policy-reader";
            var binding = new MachineCertificateBinding("service-subject", identity, true);
            boolean granted = binding.check(
                () -> MachineCertificateBindingTest.authentication("service-subject", "iam-policy-reader", java.util.List.of("policy.read")),
                new org.springframework.security.web.access.intercept.RequestAuthorizationContext(req)).isGranted();
            if (!granted) { res.setStatus(403); return; }
          }
          res.getWriter().write("OK");
        }
      }, "/");
    }
  }
  AnnotationConfigServletWebServerApplicationContext start(Map<String,Object> properties) {
    var context = new AnnotationConfigServletWebServerApplicationContext();
    context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("test", properties));
    context.register(App.class);
    try { context.refresh(); return context; }
    catch (RuntimeException e) { context.close(); throw e; }
  }
  Map<String,Object> tls(int port) {
    return Map.of("iam.machine.tls.enabled", true, "iam.machine.tls.port", port,
        "iam.machine.tls.key-store", keys.toString(), "iam.machine.tls.key-store-password", PASSWORD,
        "iam.machine.tls.trust-store", trust.toString(), "iam.machine.tls.trust-store-password", PASSWORD);
  }
  static int freePort() throws Exception { try (var socket = new java.net.ServerSocket(0)) { return socket.getLocalPort(); } }
  static HttpClient client(boolean certificate) throws Exception {
    var trustStore = KeyStore.getInstance("PKCS12");
    try (var stream = Files.newInputStream(trust)) { trustStore.load(stream, PASSWORD.toCharArray()); }
    var tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); tm.init(trustStore);
    KeyManager[] km = null;
    if (certificate) {
      var store = KeyStore.getInstance("PKCS12");
      try (var stream = Files.newInputStream(keys)) { store.load(stream, PASSWORD.toCharArray()); }
      var factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      factory.init(store, PASSWORD.toCharArray()); km = factory.getKeyManagers();
    }
    var ssl = SSLContext.getInstance("TLS"); ssl.init(km, tm.getTrustManagers(), null);
    return HttpClient.newBuilder().sslContext(ssl).connectTimeout(java.time.Duration.ofSeconds(3)).build();
  }
  static int get(HttpClient client, String url) throws Exception {
    return client.send(HttpRequest.newBuilder(URI.create(url)).timeout(java.time.Duration.ofSeconds(5))
        .header("Forwarded", "proto=https;host=localhost:8443").header("X-Forwarded-Port", "8443")
        .header("X-SSL-Client-Verify", "SUCCESS").header("Authorization", "Bearer forged")
        .build(), HttpResponse.BodyHandlers.discarding()).statusCode();
  }
  @Test void disabledDefaultHttpAndDispatchBoundary() throws Exception {
    try (var context = start(Map.of())) {
      assertFalse(context.getBean(MachineTlsProperties.class).enabled());
      assertEquals(8443, context.getBean(MachineTlsProperties.class).port());
      String base = "http://localhost:" + context.getWebServer().getPort();
      var client = HttpClient.newHttpClient();
      assertEquals(200, get(client, base + "/human"));
      for (String path : new String[]{"/api/machine", "/api/machine/test", "/api/machine/policy/health", "/forward", "/api/machine;v=1/test", "/api/%6dachine/test"})
        assertEquals(403, get(client, base + path), path);
    }
  }
  @Test void missingAndInvalidTlsFailStartup() throws Exception {
    assertThrows(RuntimeException.class, () -> start(Map.of("iam.machine.tls.enabled", true)));
    var invalid = new java.util.HashMap<>(tls(freePort()));
    invalid.put("iam.machine.tls.key-store-password", "wrong");
    assertThrows(RuntimeException.class, () -> start(invalid));
    invalid.put("iam.machine.tls.key-store", temp.resolve("missing.p12").toString());
    assertThrows(RuntimeException.class, () -> start(invalid));
  }
  @Test void realTlsRequiresClientCertificateAndSeparatesListeners() throws Exception {
    int port = freePort();
    try (var context = start(tls(port))) {
      String base = "https://localhost:" + port;
      assertThrows(java.io.IOException.class, () -> get(client(false), base + "/api/machine/test"));
      assertEquals(200, get(client(true), base + "/api/machine/test"));
      assertEquals(200, get(client(true), base + "/api/machine/binding"));
      assertEquals(403, get(client(true), base + "/api/machine/binding/wrong"));
      assertEquals(403, get(client(true), base + "/human"));
      assertEquals(403, get(client(true), base + "/api/machine/forward"));
      assertEquals(200, get(HttpClient.newHttpClient(), "http://localhost:" + context.getWebServer().getPort() + "/human"));
      assertEquals(403, get(HttpClient.newHttpClient(), "http://localhost:" + context.getWebServer().getPort() + "/api/machine/test"));
    }
  }
  @Test void prefixMappedServletCannotHideMachinePath() throws Exception {
    var request = new MockHttpServletRequest();
    request.setServletPath("/api"); request.setPathInfo("/machine/test");
    request.setAttribute(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(false));
    var response = new MockHttpServletResponse();
    new MachineListenerGuard().doFilter(request, response, (r, s) -> fail("Hidden machine path"));
    assertEquals(403, response.getStatus());
  }
  @Test void conflictingPortRejected() {
    assertThrows(IllegalStateException.class, () -> MachineTlsConfiguration.connector(
        new MachineTlsProperties(true, 8080, keys.toString(), PASSWORD, trust.toString(), PASSWORD), 8080));
  }
  @Test void everyDispatchChecksTargetAndIgnoresClaimedHeaders() throws Exception {
    var guard = new MachineListenerGuard();
    for (DispatcherType type : DispatcherType.values()) {
      var request = new MockHttpServletRequest(); request.setDispatcherType(type);
      request.setServletPath("/api/machine/test");
      request.setAttribute(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(false));
      request.addHeader("X-Forwarded-Port", "8443"); request.setSecure(true);
      if (type == DispatcherType.INCLUDE) {
        request.setServletPath("/human");
        request.setAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH, "/api/machine/test");
      }
      var response = new MockHttpServletResponse();
      FilterChain forbidden = (r, s) -> fail("Forbidden dispatch reached handler");
      if (type == DispatcherType.INCLUDE) assertThrows(ServletException.class, () -> guard.doFilter(request, response, forbidden));
      else { guard.doFilter(request, response, forbidden); assertEquals(403, response.getStatus()); }
    }
  }
}
