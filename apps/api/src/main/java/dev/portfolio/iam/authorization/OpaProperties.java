package dev.portfolio.iam.authorization;

import java.net.URI;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.opa")
public record OpaProperties(String apiUrl,
                            Duration connectTimeout, Duration requestTimeout) {
  boolean isValid() {
    try {
      URI uri = URI.create(apiUrl);
      return ("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))
        && uri.getHost() != null && uri.getUserInfo() == null
        && uri.getQuery() == null && uri.getFragment() == null
        && (uri.getPort() == -1 || (uri.getPort() > 0 && uri.getPort() <= 65535))
        && validTimeout(connectTimeout) && validTimeout(requestTimeout);
    } catch (IllegalArgumentException | NullPointerException e) {
      return false;
    }
  }

  private static boolean validTimeout(Duration timeout) {
    return timeout != null && timeout.compareTo(Duration.ofMillis(1)) >= 0
      && timeout.compareTo(Duration.ofSeconds(30)) <= 0;
  }
}
