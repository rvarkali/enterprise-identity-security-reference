package dev.portfolio.iam.machine;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.machine.tls")
public record MachineTlsProperties(boolean enabled, Integer port, String keyStore,
    String keyStorePassword, String trustStore, String trustStorePassword) {
  public MachineTlsProperties {
    if (port == null) port = 8443;
  }
}
