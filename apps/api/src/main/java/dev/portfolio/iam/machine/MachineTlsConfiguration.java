package dev.portfolio.iam.machine;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.EnumSet;
import jakarta.servlet.DispatcherType;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.valves.ValveBase;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(MachineTlsProperties.class)
public class MachineTlsConfiguration {
  @Bean
  WebServerFactoryCustomizer<TomcatServletWebServerFactory> machineConnector(MachineTlsProperties p) {
    return factory -> {
      Connector machine = p.enabled() ? connector(p, factory.getPort()) : null;
      if (machine != null) factory.addAdditionalTomcatConnectors(machine);
      factory.addContextValves(new ValveBase(true) {
        @Override
        public void invoke(org.apache.catalina.connector.Request request,
                           org.apache.catalina.connector.Response response)
            throws java.io.IOException, jakarta.servlet.ServletException {
          // Connector identity and socket local port are container evidence, never headers.
          boolean onMachine = machine != null && request.getConnector() == machine
              && request.getLocalPort() == machine.getLocalPort() && request.isSecure();
          request.setAttribute(MachineListenerGuard.TRANSPORT, new MachineListenerGuard.Transport(onMachine));
          getNext().invoke(request, response);
        }
      });
    };
  }

  @Bean
  FilterRegistrationBean<MachineListenerGuard> machineListenerGuard() {
    var registration = new FilterRegistrationBean<>(new MachineListenerGuard());
    registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
    registration.setDispatcherTypes(EnumSet.allOf(DispatcherType.class));
    registration.setAsyncSupported(true);
    registration.addUrlPatterns("/*");
    return registration;
  }

  static Connector connector(MachineTlsProperties p, int httpPort) {
    try {
      if (p.port() < 1 || p.port() > 65535 || p.port() == httpPort) throw new IllegalArgumentException();
      KeyStore keys = load(p.keyStore(), p.keyStorePassword());
      KeyStore trust = load(p.trustStore(), p.trustStorePassword());
      String alias = null;
      for (String candidate : Collections.list(keys.aliases())) {
        if (keys.isKeyEntry(candidate)) {
          if (alias != null || !(keys.getKey(candidate, p.keyStorePassword().toCharArray()) instanceof PrivateKey))
            throw new IllegalArgumentException();
          alias = candidate;
          var chain = keys.getCertificateChain(candidate);
          if (chain == null || chain.length == 0) throw new IllegalArgumentException();
          for (var cert : chain) ((X509Certificate) cert).checkValidity();
        }
      }
      if (alias == null || trust.size() == 0) throw new IllegalArgumentException();
      for (String candidate : Collections.list(trust.aliases())) {
        if (!trust.isCertificateEntry(candidate)) throw new IllegalArgumentException();
        var cert = (X509Certificate) trust.getCertificate(candidate);
        cert.checkValidity();
        if (cert.getBasicConstraints() < 0) throw new IllegalArgumentException();
      }
      var ssl = new SSLHostConfig();
      ssl.setProtocols("TLSv1.2,TLSv1.3");
      ssl.setCertificateVerification("required");
      ssl.setTrustStore(trust);
      var certificate = new SSLHostConfigCertificate(ssl, SSLHostConfigCertificate.Type.UNDEFINED);
      certificate.setCertificateKeystore(keys);
      certificate.setCertificateKeystorePassword(p.keyStorePassword());
      certificate.setCertificateKeyPassword(p.keyStorePassword());
      certificate.setCertificateKeyAlias(alias);
      ssl.addCertificate(certificate);
      var connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
      connector.setPort(p.port());
      connector.setScheme("https");
      connector.setSecure(true);
      connector.setProperty("SSLEnabled", "true");
      connector.setThrowOnFailure(true);
      connector.addSslHostConfig(ssl);
      return connector;
    } catch (Exception e) {
      // Do not expose store passwords or provider messages.
      throw new IllegalStateException("Invalid machine TLS configuration (PKCS12 key/trust stores required)");
    }
  }

  private static KeyStore load(String file, String password) throws Exception {
    if (file == null || file.isBlank() || password == null || password.isBlank()) throw new IllegalArgumentException();
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (InputStream stream = Files.newInputStream(Path.of(file))) { store.load(stream, password.toCharArray()); }
    return store;
  }
}
