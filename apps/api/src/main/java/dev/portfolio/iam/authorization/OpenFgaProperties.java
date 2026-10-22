package dev.portfolio.iam.authorization;

import java.net.URI;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.openfga")
public record OpenFgaProperties(String apiUrl, String storeId, String authorizationModelId,
                                Duration connectTimeout, Duration requestTimeout) {
  boolean isValid() {
    try {
      URI uri = URI.create(apiUrl);
      return ("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))
        && uri.getHost() != null && uri.getUserInfo() == null
        && uri.getQuery() == null && uri.getFragment() == null
        && (uri.getPort() == -1 || (uri.getPort() > 0 && uri.getPort() <= 65535))
        && validId(storeId) && validId(authorizationModelId)
        && validTimeout(connectTimeout) && validTimeout(requestTimeout);
    } catch (IllegalArgumentException | NullPointerException e) {
      return false;
    }
  }

  private static boolean validId(String id) {
    return id != null && id.matches("[0-7][0-9A-HJKMNP-TV-Z]{25}");
  }

  private static boolean validTimeout(Duration timeout) {
    return timeout != null && timeout.compareTo(Duration.ofMillis(1)) >= 0
      && timeout.compareTo(Duration.ofSeconds(30)) <= 0;
  }
}
